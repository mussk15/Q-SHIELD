"""Network Monitoring Service Adapter for Q-SHIELD Dashboard.

Provides both offline PCAP analysis and live Scapy network monitoring,
integrating with the sliding-window feature extractor, rule-based IDS,
and Isolation Forest anomaly detector.
"""
from __future__ import annotations

import collections
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, ICMP, conf, get_if_list, rdpcap, sniff  # type: ignore

from qshield.monitor.alerts import AlertManager
from qshield.monitor.anomaly import IsolationForestAnomalyDetector
from qshield.monitor.features import PacketRecord, SlidingWindowFeatureExtractor
from qshield.monitor.rules import RuleEngine, load_config
from qshield.monitor.sniffer import packet_to_record


class MonitorService:
    """Manages offline PCAP analysis and live network capture."""

    def __init__(self, alerts_path: str | Path = "data/alerts.jsonl"):
        self.alerts_path = Path(alerts_path)
        self.alert_manager = AlertManager(str(self.alerts_path), cooldown_seconds=10)
        self.rule_config = load_config()
        self.rule_engine = RuleEngine(self.rule_config, self.alert_manager)

        # Live capture state
        self._is_capturing = False
        self._capture_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._live_packet_count = 0
        self._live_protocols: dict[str, int] = collections.defaultdict(int)
        self._live_src_ips: dict[str, int] = collections.defaultdict(int)
        self._live_dst_ips: dict[str, int] = collections.defaultdict(int)
        self._live_alerts_generated: list[dict[str, Any]] = []
        self._live_started_at: str | None = None
        self._live_interface: str | None = None
        self._live_extractor = SlidingWindowFeatureExtractor(window_seconds=10.0)

    @staticmethod
    def list_interfaces() -> list[dict[str, str]]:
        """List network interfaces with descriptions and IP addresses."""
        results = []
        raw_list = get_if_list()
        for name in raw_list:
            iface_obj = conf.ifaces.get(name)
            desc = iface_obj.description if iface_obj else name
            ip = getattr(iface_obj, "ip", "") if iface_obj else ""
            results.append({
                "id": str(name),
                "name": str(getattr(iface_obj, "name", name)),
                "description": str(desc),
                "ip": str(ip) if ip else "No IPv4",
            })
        return results

    def analyze_pcap(
        self,
        pcap_path: str | Path,
        model_path: str | Path = "data/anomaly_model.joblib",
    ) -> dict[str, Any]:
        """Perform full packet inspection, feature extraction and IDS analysis on a PCAP."""
        target_path = Path(pcap_path)
        if not target_path.exists():
            return {"success": False, "message": f"PCAP file not found: {target_path}"}

        # 1. Load ML model if present
        model: IsolationForestAnomalyDetector | None = None
        model_file = Path(model_path)
        if model_file.exists():
            try:
                import joblib
                loaded = joblib.load(model_file)
                if isinstance(loaded, IsolationForestAnomalyDetector):
                    model = loaded
            except Exception:
                pass

        # 2. Read packets with Scapy
        try:
            packets = rdpcap(str(target_path))
        except Exception as exc:
            return {"success": False, "message": f"Failed to parse PCAP: {exc}"}

        total_packets = len(packets)
        total_bytes = 0
        protocol_counts: dict[str, int] = collections.defaultdict(int)
        src_ips: dict[str, int] = collections.defaultdict(int)
        dst_ips: dict[str, int] = collections.defaultdict(int)
        dst_ports: dict[int, int] = collections.defaultdict(int)
        tcp_flags: dict[str, int] = collections.defaultdict(int)

        extractor = SlidingWindowFeatureExtractor(window_seconds=10.0)
        alerts_emitted = []
        anomaly_scores = []
        window_start: float | None = None
        latest_timestamp: float | None = None

        for pkt in packets:
            pkt_len = len(pkt)
            total_bytes += pkt_len

            if TCP in pkt:
                protocol_counts["TCP"] += 1
                tcp_flags[str(pkt[TCP].flags)] += 1
                dst_ports[int(pkt[TCP].dport)] += 1
            elif UDP in pkt:
                protocol_counts["UDP"] += 1
                dst_ports[int(pkt[UDP].dport)] += 1
            elif ICMP in pkt:
                protocol_counts["ICMP"] += 1
            else:
                protocol_counts["Other"] += 1

            if IP in pkt:
                src_ips[str(pkt[IP].src)] += 1
                dst_ips[str(pkt[IP].dst)] += 1
            elif IPv6 in pkt:
                src_ips[str(pkt[IPv6].src)] += 1
                dst_ips[str(pkt[IPv6].dst)] += 1

            record = packet_to_record(pkt)
            if record is not None:
                extractor.add_packet(record)
                if window_start is None:
                    window_start = record.timestamp
                latest_timestamp = record.timestamp

                if latest_timestamp - window_start >= 10.0:
                    windows = extractor.snapshot(now=latest_timestamp)
                    for window in windows:
                        detected = self.rule_engine.evaluate_window(window)
                        for alert in detected:
                            alerts_emitted.append(alert.to_dict())

                        if model is not None and getattr(model, "_fitted", False):
                            try:
                                res = model.predict_one(window)
                                anomaly_scores.append(res.anomaly_score)
                                if res.is_anomaly:
                                    alert = self.alert_manager.create(
                                        source_ip=window.src_ip,
                                        rule_id="ML_ANOMALY",
                                        title=f"Statistical Traffic Anomaly ({window.src_ip})",
                                        description=f"Isolation Forest anomaly score: {res.anomaly_score:.3f}",
                                        severity="HIGH" if res.anomaly_score > 0.2 else "MEDIUM",
                                        score=85 if res.anomaly_score > 0.2 else 65,
                                        evidence={"anomaly_score": res.anomaly_score, "features": window.to_dict()},
                                    )
                                    if alert:
                                        alerts_emitted.append(alert.to_dict())
                            except Exception:
                                pass
                    extractor.clear()
                    window_start = latest_timestamp

        # Flush remaining windows
        if latest_timestamp is not None:
            final_windows = extractor.snapshot(now=latest_timestamp)
            for window in final_windows:
                detected = self.rule_engine.evaluate_window(window)
                for alert in detected:
                    alerts_emitted.append(alert.to_dict())
            extractor.clear()

        return {
            "success": True,
            "filename": target_path.name,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocol_counts": dict(protocol_counts),
            "top_src_ips": sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:8],
            "top_dst_ips": sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:8],
            "top_ports": sorted(dst_ports.items(), key=lambda x: x[1], reverse=True)[:8],
            "tcp_flags": dict(tcp_flags),
            "alerts_count": len(alerts_emitted),
            "alerts": alerts_emitted,
            "anomaly_scores_count": len(anomaly_scores),
            "mean_anomaly_score": (sum(anomaly_scores) / len(anomaly_scores)) if anomaly_scores else None,
        }

    def start_live_capture(self, interface: str | None = None, bpf_filter: str = "tcp") -> dict[str, Any]:
        """Start real-time packet capture on the selected network interface."""
        with self._lock:
            if self._is_capturing:
                return {"success": True, "message": "Live monitoring is already running."}

            self._stop_event.clear()
            self._live_packet_count = 0
            self._live_protocols.clear()
            self._live_src_ips.clear()
            self._live_dst_ips.clear()
            self._live_alerts_generated.clear()
            self._live_started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._live_interface = interface or "Default"
            self._live_extractor = SlidingWindowFeatureExtractor(window_seconds=10.0)

            def capture_worker():
                def handle_live_packet(pkt):
                    if self._stop_event.is_set():
                        return

                    with self._lock:
                        self._live_packet_count += 1
                        if TCP in pkt:
                            self._live_protocols["TCP"] += 1
                        elif UDP in pkt:
                            self._live_protocols["UDP"] += 1
                        elif ICMP in pkt:
                            self._live_protocols["ICMP"] += 1
                        else:
                            self._live_protocols["Other"] += 1

                        if IP in pkt:
                            self._live_src_ips[str(pkt[IP].src)] += 1
                            self._live_dst_ips[str(pkt[IP].dst)] += 1

                    record = packet_to_record(pkt)
                    if record is not None:
                        self._live_extractor.add_packet(record)
                        windows = self._live_extractor.snapshot(now=record.timestamp)
                        for window in windows:
                            alerts = self.rule_engine.evaluate_window(window)
                            for a in alerts:
                                with self._lock:
                                    self._live_alerts_generated.append(a.to_dict())

                try:
                    sniff(
                        iface=interface if interface != "Default" else None,
                        filter=bpf_filter,
                        prn=handle_live_packet,
                        store=False,
                        stop_filter=lambda _: self._stop_event.is_set(),
                    )
                except Exception as exc:
                    print(f"[LIVE CAPTURE ERROR] {exc}")

            self._capture_thread = threading.Thread(
                target=capture_worker, name="qshield-live-sniffer", daemon=True
            )
            self._capture_thread.start()
            self._is_capturing = True

            return {"success": True, "message": f"Live capture active on interface '{self._live_interface}'"}

    def stop_live_capture(self) -> dict[str, Any]:
        """Stop real-time packet capture cleanly."""
        with self._lock:
            if not self._is_capturing:
                return {"success": True, "message": "Live monitoring is not running."}

            self._stop_event.set()
            if self._capture_thread and self._capture_thread.is_alive():
                self._capture_thread.join(timeout=2.0)
                self._capture_thread = None

            self._is_capturing = False
            return {
                "success": True,
                "message": f"Live capture stopped. Captured {self._live_packet_count} packets.",
                "total_packets": self._live_packet_count,
            }

    def get_live_stats(self) -> dict[str, Any]:
        """Return current live capture statistics."""
        with self._lock:
            return {
                "is_capturing": self._is_capturing,
                "interface": self._live_interface,
                "started_at": self._live_started_at,
                "packet_count": self._live_packet_count,
                "protocols": dict(self._live_protocols),
                "top_src_ips": sorted(self._live_src_ips.items(), key=lambda x: x[1], reverse=True)[:5],
                "top_dst_ips": sorted(self._live_dst_ips.items(), key=lambda x: x[1], reverse=True)[:5],
                "alerts_count": len(self._live_alerts_generated),
                "recent_alerts": list(self._live_alerts_generated[-5:]),
            }
