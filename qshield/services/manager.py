"""Unified Service Manager Singleton for Q-SHIELD Dashboard.

Provides a thread-safe central registry connecting the Streamlit UI
to backend networking, cryptography, file transfer, and monitoring services.
"""
from __future__ import annotations

import threading
from typing import Any

from qshield.services.client_service import ClientService
from qshield.services.file_transfer_service import FileTransferService
from qshield.services.monitor_service import MonitorService
from qshield.services.server_service import ServerService


class ServiceManager:
    """Central service coordinator for Q-SHIELD."""

    _instance: ServiceManager | None = None
    _singleton_lock = threading.Lock()

    def __init__(self):
        self.server = ServerService()
        self.client = ClientService()
        self.file_transfer = FileTransferService()
        self.monitor = MonitorService()

    @classmethod
    def get_instance(cls) -> ServiceManager:
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def get_system_health(self) -> dict[str, Any]:
        """Aggregate health metrics across all managed backend subsystems."""
        server_status = self.server.get_status()
        client_status = self.client.get_status()
        live_stats = self.monitor.get_live_stats()
        file_server_active = self.file_transfer.is_port_in_use("127.0.0.1", 5002)

        return {
            "server": server_status,
            "client": client_status,
            "monitor": live_stats,
            "file_server": {
                "active": file_server_active,
                "port": 5002,
                "received_count": len(self.file_transfer.list_received_files()),
            },
        }


def get_service_manager() -> ServiceManager:
    """Return the global ServiceManager singleton."""
    return ServiceManager.get_instance()

