"""Q-SHIELD service layer for dashboard integration.

Provides clean, thread-safe service adapters for:
- ServerService: Secure TCP server lifecycle management.
- ClientService: Post-quantum secure client and encrypted messaging.
- FileTransferService: Encrypted chunk-based file transfer with SHA-256 integrity.
- MonitorService: PCAP traffic replay analysis and live Scapy network capture.
- ServiceManager: Central singleton registry.
"""
from __future__ import annotations

from qshield.services.manager import ServiceManager, get_service_manager
from qshield.services.server_service import ServerService
from qshield.services.client_service import ClientService
from qshield.services.file_transfer_service import FileTransferService
from qshield.services.monitor_service import MonitorService

__all__ = [
    "ServiceManager",
    "get_service_manager",
    "ServerService",
    "ClientService",
    "FileTransferService",
    "MonitorService",
]

