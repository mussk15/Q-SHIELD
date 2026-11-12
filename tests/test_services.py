"""Unit and integration tests for Q-SHIELD service adapters."""
from __future__ import annotations

import socket
import tempfile
from pathlib import Path

import pytest

from qshield.services.client_service import ClientService
from qshield.services.file_transfer_service import FileTransferService
from qshield.services.manager import get_service_manager
from qshield.services.monitor_service import MonitorService
from qshield.services.server_service import ServerService


def test_service_manager_singleton():
    mgr1 = get_service_manager()
    mgr2 = get_service_manager()
    assert mgr1 is mgr2
    health = mgr1.get_system_health()
    assert "server" in health
    assert "client" in health
    assert "monitor" in health
    assert "file_server" in health


def test_server_service_port_in_use_detection():
    # Bind a temporary socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    try:
        assert ServerService.is_port_in_use("127.0.0.1", port) is True
    finally:
        sock.close()

    assert ServerService.is_port_in_use("127.0.0.1", port) is False


def test_server_service_start_and_stop():
    server = ServerService()
    # Find free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]

    res = server.start_server(host="127.0.0.1", port=free_port, password="QSHIELD")
    assert res["success"] is True

    status = server.get_status()
    assert status["status"] == "RUNNING"
    assert status["managed"] is True
    assert status["port"] == free_port

    stop_res = server.stop_server()
    assert stop_res["success"] is True
    assert server.get_status()["status"] == "STOPPED"


def test_client_and_server_messaging_integration():
    server = ServerService()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]

    start_res = server.start_server(host="127.0.0.1", port=free_port, password="QSHIELD")
    assert start_res["success"] is True

    client = ClientService()
    try:
        conn_res = client.connect(host="127.0.0.1", port=free_port, password="QSHIELD")
        assert conn_res["success"] is True
        assert client.is_connected is True
        assert client.get_status()["generation"] == 0

        # Send encrypted message
        msg_res = client.send_encrypted_message("Test Post-Quantum Message 1")
        assert msg_res["success"] is True
        assert "Test Post-Quantum Message 1" in msg_res["received"]
        assert msg_res["generation"] == 0

        # Send another message
        msg_res2 = client.send_encrypted_message("Test Post-Quantum Message 2")
        assert msg_res2["success"] is True

        history = client.get_status()["history"]
        assert len(history) == 2
        assert history[0]["sent"] == "Test Post-Quantum Message 1"
        assert history[1]["sent"] == "Test Post-Quantum Message 2"

        # Disconnect
        disc_res = client.disconnect()
        assert disc_res["success"] is True
        assert client.is_connected is False
    finally:
        server.stop_server()


def test_monitor_service_pcap_analysis():
    monitor = MonitorService()
    pcap_file = Path("data/port_scan.pcapng")
    if not pcap_file.exists():
        pytest.skip("data/port_scan.pcapng not present")

    res = monitor.analyze_pcap(pcap_file)
    assert res["success"] is True
    assert res["total_packets"] > 0
    assert "TCP" in res["protocol_counts"]
    assert len(res["top_src_ips"]) > 0
    assert len(res["top_dst_ips"]) > 0


def test_monitor_service_list_interfaces():
    interfaces = MonitorService.list_interfaces()
    assert isinstance(interfaces, list)
    assert len(interfaces) > 0
    assert "id" in interfaces[0]
    assert "name" in interfaces[0]


def test_file_transfer_service_end_to_end(tmp_path):
    import secrets
    fts = FileTransferService()
    fname = f"transfer_test_{secrets.token_hex(4)}.txt"
    test_file = tmp_path / fname
    test_file.write_bytes(b"Secret Q-SHIELD document payload for service testing.")

    res = fts.send_file(test_file, password="QSHIELD")
    assert res["success"] is True
    assert res["status"] == "VERIFIED"
    assert res["filename"] == fname
    assert res["size_bytes"] == len(b"Secret Q-SHIELD document payload for service testing.")

    received = fts.list_received_files()
    assert any(f["filename"] == fname for f in received)
