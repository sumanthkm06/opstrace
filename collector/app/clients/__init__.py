"""
OpsTrace HTTP Transport and API Ingestion Clients
Phase 4: Linux Monitoring Collector
"""

from collector.app.clients.backend import BackendClient, build_client_from_settings

__all__ = ["BackendClient", "build_client_from_settings"]
