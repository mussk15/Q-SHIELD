"""Deployment health-check utility for Q-SHIELD components."""
from __future__ import annotations

import argparse
import os
import socket
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from response.evidence import verify_chain


def check_tcp_server(host: str, port: int, timeout: float = 2.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP server reachable at {host}:{port}"
    except (OSError, ConnectionRefusedError) as exc:
        return False, f"TCP server unreachable at {host}:{port} ({exc})"


def check_http_dashboard(url: str, timeout: float = 3.0) -> tuple[bool, str]:
    try:
        req = Request(url, headers={"User-Agent": "Q-SHIELD-HealthCheck/1.0"})
        with urlopen(req, timeout=timeout) as response:
            code = response.getcode()
            if 200 <= code < 400:
                return True, f"Dashboard HTTP {code} OK at {url}"
            return False, f"Dashboard returned unexpected status {code} at {url}"
    except Exception as exc:
        return False, f"Dashboard request failed for {url} ({exc})"


def check_evidence(data_dir: Path) -> tuple[bool, str]:
    evidence_file = data_dir / "evidence.jsonl"
    valid, msg = verify_chain(evidence_file)
    return valid, f"Evidence chain: {msg}"


def main():
    parser = argparse.ArgumentParser(description="Q-SHIELD Component Health Check")
    parser.add_argument("--server-host", default=os.getenv("QSHIELD_SERVER_HOST", "127.0.0.1"))
    parser.add_argument("--server-port", type=int, default=int(os.getenv("QSHIELD_SERVER_PORT", "5001")))
    parser.add_argument("--dashboard-url", default=os.getenv("QSHIELD_DASHBOARD_URL", "http://127.0.0.1:8501"))
    parser.add_argument("--skip-dashboard", action="store_true")
    parser.add_argument("--skip-server", action="store_true")
    args = parser.parse_args()

    data_dir = Path(os.getenv("QSHIELD_DATA_DIR", "data"))
    if not data_dir.is_absolute():
        data_dir = ROOT / data_dir

    all_ok = True
    print("=" * 60)
    print("Q-SHIELD SYSTEM HEALTH CHECK")
    print("=" * 60)

    # 1. TCP Server
    if not args.skip_server:
        srv_ok, srv_msg = check_tcp_server(args.server_host, args.server_port)
        status = "[PASS]" if srv_ok else "[FAIL]"
        print(f"{status} Secure TCP Server: {srv_msg}")
        if not srv_ok:
            all_ok = False

    # 2. HTTP Dashboard
    if not args.skip_dashboard:
        dash_ok, dash_msg = check_http_dashboard(args.dashboard_url)
        status = "[PASS]" if dash_ok else "[FAIL]"
        print(f"{status} Dashboard Service: {dash_msg}")
        if not dash_ok:
            all_ok = False

    # 3. Evidence Integrity
    ev_ok, ev_msg = check_evidence(data_dir)
    status = "[PASS]" if ev_ok else "[FAIL]"
    print(f"{status} Storage Integrity: {ev_msg}")
    if not ev_ok:
        all_ok = False

    print("=" * 60)
    if all_ok:
        print("OVERALL STATUS: HEALTHY")
        sys.exit(0)
    else:
        print("OVERALL STATUS: DEGRADED / UNHEALTHY")
        sys.exit(1)


if __name__ == "__main__":
    main()

