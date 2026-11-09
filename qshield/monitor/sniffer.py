"""Scapy packet capture and PCAP replay adapter."""
from __future__ import annotations

from typing import Callable
from scapy.all import IP, IPv6, TCP, sniff, rdpcap  # type: ignore

from .features import PacketRecord


def packet_to_record(packet) -> PacketRecord | None:
    """Convert an IP/TCP packet into a compact record; ignore other protocols."""
    if TCP not in packet:
        return None

    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
    else:
        return None

    tcp = packet[TCP]
    try:
        timestamp = float(packet.time)
    except (AttributeError, TypeError, ValueError):
        return None

    return PacketRecord(
        timestamp=timestamp,
        src_ip=str(src_ip),
        dst_ip=str(dst_ip),
        src_port=int(tcp.sport),
        dst_port=int(tcp.dport),
        flags=str(tcp.flags),
        packet_bytes=len(packet),
    )


def capture_live(callback: Callable[[PacketRecord], None], interface: str | None = None,
                 duration: int = 60, bpf_filter: str = "tcp") -> None:
    """Capture for a bounded duration. Requires suitable OS capture permissions."""
    if duration <= 0:
        raise ValueError("duration must be positive")

    def handle(packet):
        record = packet_to_record(packet)
        if record is not None:
            callback(record)

    sniff(iface=interface, filter=bpf_filter, prn=handle, store=False, timeout=duration)


def replay_pcap(path: str, callback: Callable[[PacketRecord], None]) -> int:
    """Replay a PCAP file without transmitting packets."""
    count = 0
    for packet in rdpcap(path):
        record = packet_to_record(packet)
        if record is not None:
            callback(record)
            count += 1
    return count
