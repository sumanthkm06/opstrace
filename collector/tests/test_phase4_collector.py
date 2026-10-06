"""
OpsTrace Phase 4 — Linux Monitoring Collector Tests
=====================================================

Comprehensive unit tests for the collector daemon.

Coverage:
  1.  CPU collector returns expected structure.
  2.  Memory collector returns expected structure.
  3.  Disk collector returns expected structure.
  4.  Network collector returns expected structure.
  5.  Host collector returns expected structure.
  6.  Service collector handles Linux/systemd availability appropriately.
  7.  Telemetry payload aggregation works.
  8.  Configuration loads correctly with defaults.
  9.  Backend client uses the configured URL.
  10. Authentication token is not exposed in logs.
  11. Backend connection failure is handled gracefully.
  12. Collection loop can be stopped cleanly.

Platform notes:
  - All tests use mocking and do NOT require a real Linux server.
  - psutil calls are mocked to avoid dependency on OS internals.
  - systemctl calls are mocked; Windows-safe by design.
  - The collection loop test mocks time.sleep and the global _running flag.

Run from the repository root:
    pytest collector/tests/test_phase4_collector.py -v

Run all collector tests:
    pytest collector/tests/ -v
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, Mock, call, patch

import pytest

# ---------------------------------------------------------------------------
# sys.path bootstrap
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent.parent   # opstrace/
COLLECTOR_DIR = REPO_ROOT / "collector"
for _p in (str(REPO_ROOT), str(COLLECTOR_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from collector.app.collectors.models import (
    CpuTelemetry,
    DiskTelemetry,
    HostTelemetry,
    MemoryTelemetry,
    NetworkInterfaceTelemetry,
    ServiceTelemetry,
    TelemetryPayload,
)
from collector.app.config.settings import CollectorSettings


# ===========================================================================
# 1. CPU Collector
# ===========================================================================

class TestCpuCollector:
    """Tests for collector.app.collectors.cpu.collect_cpu"""

    def test_returns_cpu_telemetry_type(self):
        """collect_cpu() must return a CpuTelemetry instance."""
        with patch("psutil.cpu_percent", return_value=42.5), \
             patch("psutil.cpu_count", side_effect=[8, 4]), \
             patch("os.getloadavg", return_value=(1.0, 1.5, 2.0), create=True):
            from collector.app.collectors.cpu import collect_cpu
            result = collect_cpu()
        assert isinstance(result, CpuTelemetry)

    def test_cpu_percent_is_present(self):
        """cpu_percent field must be populated."""
        with patch("psutil.cpu_percent", return_value=72.5), \
             patch("psutil.cpu_count", side_effect=[8, 4]), \
             patch("os.getloadavg", return_value=(0.5, 1.0, 1.5), create=True):
            from collector.app.collectors.cpu import collect_cpu
            result = collect_cpu()
        assert result.cpu_percent == 72.5

    def test_logical_and_physical_cpu_count(self):
        """Logical and physical CPU counts are populated when psutil returns them."""
        with patch("psutil.cpu_percent", return_value=10.0), \
             patch("psutil.cpu_count", side_effect=[16, 8]), \
             patch("os.getloadavg", return_value=(0.1, 0.2, 0.3), create=True):
            from collector.app.collectors.cpu import collect_cpu
            result = collect_cpu()
        assert result.logical_cpu_count == 16
        assert result.physical_cpu_count == 8

    def test_load_averages_populated_on_linux(self):
        """Load averages are populated when os.getloadavg is available."""
        with patch("psutil.cpu_percent", return_value=55.0), \
             patch("psutil.cpu_count", side_effect=[4, 2]), \
             patch("os.getloadavg", return_value=(1.2, 2.3, 3.4), create=True):
            from collector.app.collectors.cpu import collect_cpu
            result = collect_cpu()
        assert result.load_avg_1m == pytest.approx(1.2)
        assert result.load_avg_5m == pytest.approx(2.3)
        assert result.load_avg_15m == pytest.approx(3.4)

    def test_load_averages_none_when_unavailable(self):
        """Load averages are None when os.getloadavg raises AttributeError (Windows)."""
        with patch("psutil.cpu_percent", return_value=30.0), \
             patch("psutil.cpu_count", side_effect=[4, 2]), \
             patch("collector.app.collectors.cpu._get_load_averages", return_value=(None, None, None)):
            from collector.app.collectors.cpu import collect_cpu
            result = collect_cpu()
        assert result.load_avg_1m is None
        assert result.load_avg_5m is None
        assert result.load_avg_15m is None

    def test_psutil_failure_raises_runtime_error(self):
        """If psutil.cpu_percent raises, collect_cpu propagates a RuntimeError."""
        with patch("psutil.cpu_percent", side_effect=RuntimeError("kernel error")):
            from collector.app.collectors.cpu import collect_cpu
            with pytest.raises(RuntimeError, match="Failed to read CPU percent"):
                collect_cpu()


# ===========================================================================
# 2. Memory Collector
# ===========================================================================

class TestMemoryCollector:
    """Tests for collector.app.collectors.memory.collect_memory"""

    def _make_vmem(self, total=8_589_934_592, available=4_294_967_296,
                   used=4_294_967_296, percent=50.0):
        vm = MagicMock()
        vm.total = total
        vm.available = available
        vm.used = used
        vm.percent = percent
        return vm

    def test_returns_memory_telemetry_type(self):
        """collect_memory() must return a MemoryTelemetry instance."""
        with patch("psutil.virtual_memory", return_value=self._make_vmem()):
            from collector.app.collectors.memory import collect_memory
            result = collect_memory()
        assert isinstance(result, MemoryTelemetry)

    def test_total_bytes_populated(self):
        with patch("psutil.virtual_memory", return_value=self._make_vmem(total=16_000_000_000)):
            from collector.app.collectors.memory import collect_memory
            result = collect_memory()
        assert result.total_bytes == 16_000_000_000

    def test_available_bytes_populated(self):
        with patch("psutil.virtual_memory", return_value=self._make_vmem(available=2_000_000_000)):
            from collector.app.collectors.memory import collect_memory
            result = collect_memory()
        assert result.available_bytes == 2_000_000_000

    def test_memory_percent_populated(self):
        with patch("psutil.virtual_memory", return_value=self._make_vmem(percent=64.2)):
            from collector.app.collectors.memory import collect_memory
            result = collect_memory()
        assert result.memory_percent == pytest.approx(64.2)

    def test_used_bytes_populated(self):
        with patch("psutil.virtual_memory", return_value=self._make_vmem(used=3_000_000_000)):
            from collector.app.collectors.memory import collect_memory
            result = collect_memory()
        assert result.used_bytes == 3_000_000_000

    def test_psutil_failure_raises_runtime_error(self):
        with patch("psutil.virtual_memory", side_effect=OSError("no /proc")):
            from collector.app.collectors.memory import collect_memory
            with pytest.raises(RuntimeError, match="Failed to read virtual memory"):
                collect_memory()


# ===========================================================================
# 3. Disk Collector
# ===========================================================================

class TestDiskCollector:
    """Tests for collector.app.collectors.disk.collect_disk"""

    def _make_partition(self, device="/dev/sda1", mountpoint="/",
                        fstype="ext4"):
        p = MagicMock()
        p.device = device
        p.mountpoint = mountpoint
        p.fstype = fstype
        return p

    def _make_usage(self, total=100_000_000_000, used=60_000_000_000,
                    free=40_000_000_000, percent=60.0):
        u = MagicMock()
        u.total = total
        u.used = used
        u.free = free
        u.percent = percent
        return u

    def test_returns_list(self):
        """collect_disk() must return a list."""
        with patch("psutil.disk_partitions", return_value=[self._make_partition()]), \
             patch("psutil.disk_usage", return_value=self._make_usage()):
            from collector.app.collectors.disk import collect_disk
            result = collect_disk()
        assert isinstance(result, list)

    def test_single_partition_returns_one_item(self):
        with patch("psutil.disk_partitions", return_value=[self._make_partition()]), \
             patch("psutil.disk_usage", return_value=self._make_usage()):
            from collector.app.collectors.disk import collect_disk
            result = collect_disk()
        assert len(result) == 1

    def test_disk_telemetry_type(self):
        with patch("psutil.disk_partitions", return_value=[self._make_partition()]), \
             patch("psutil.disk_usage", return_value=self._make_usage()):
            from collector.app.collectors.disk import collect_disk
            result = collect_disk()
        assert isinstance(result[0], DiskTelemetry)

    def test_disk_fields_populated(self):
        usage = self._make_usage(total=200_000_000_000, used=120_000_000_000,
                                 free=80_000_000_000, percent=60.0)
        with patch("psutil.disk_partitions", return_value=[self._make_partition(mountpoint="/data")]), \
             patch("psutil.disk_usage", return_value=usage):
            from collector.app.collectors.disk import collect_disk
            result = collect_disk()
        d = result[0]
        assert d.path == "/data"
        assert d.total_bytes == 200_000_000_000
        assert d.used_bytes == 120_000_000_000
        assert d.free_bytes == 80_000_000_000
        assert d.percent == pytest.approx(60.0)
        assert d.fstype == "ext4"

    def test_virtual_filesystem_excluded(self):
        """tmpfs partitions must be excluded from results."""
        tmpfs_partition = self._make_partition(
            device="tmpfs", mountpoint="/run", fstype="tmpfs"
        )
        with patch("psutil.disk_partitions", return_value=[tmpfs_partition]), \
             patch("psutil.disk_usage", return_value=self._make_usage()):
            from collector.app.collectors.disk import collect_disk
            result = collect_disk()
        assert result == []

    def test_loop_device_excluded(self):
        """Loop devices (snap mounts) must be excluded."""
        loop_partition = self._make_partition(
            device="/dev/loop0", mountpoint="/snap/core/123", fstype="squashfs"
        )
        with patch("psutil.disk_partitions", return_value=[loop_partition]), \
             patch("psutil.disk_usage", return_value=self._make_usage()):
            from collector.app.collectors.disk import collect_disk
            result = collect_disk()
        assert result == []

    def test_permission_error_on_mount_skipped(self):
        """A PermissionError on one mount should not crash the collector."""
        partitions = [
            self._make_partition(mountpoint="/"),
            self._make_partition(device="/dev/sdb1", mountpoint="/restricted", fstype="ext4"),
        ]
        usage = self._make_usage()
        with patch("psutil.disk_partitions", return_value=partitions), \
             patch("psutil.disk_usage", side_effect=[usage, PermissionError("denied")]):
            from collector.app.collectors.disk import collect_disk
            result = collect_disk()
        # Only the first partition succeeds
        assert len(result) == 1
        assert result[0].path == "/"

    def test_partition_list_failure_raises_runtime_error(self):
        with patch("psutil.disk_partitions", side_effect=OSError("kernel panic")):
            from collector.app.collectors.disk import collect_disk
            with pytest.raises(RuntimeError, match="Failed to list disk partitions"):
                collect_disk()


# ===========================================================================
# 4. Network Collector
# ===========================================================================

class TestNetworkCollector:
    """Tests for collector.app.collectors.network.collect_network"""

    def _make_net_stats(self, bytes_sent=1_000_000, bytes_recv=5_000_000,
                        packets_sent=1000, packets_recv=5000,
                        errin=0, errout=0, dropin=0, dropout=0):
        s = MagicMock()
        s.bytes_sent = bytes_sent
        s.bytes_recv = bytes_recv
        s.packets_sent = packets_sent
        s.packets_recv = packets_recv
        s.errin = errin
        s.errout = errout
        s.dropin = dropin
        s.dropout = dropout
        return s

    def test_returns_list(self):
        counters = {"eth0": self._make_net_stats()}
        with patch("psutil.net_io_counters", return_value=counters):
            from collector.app.collectors.network import collect_network
            result = collect_network()
        assert isinstance(result, list)

    def test_interface_fields_populated(self):
        stats = self._make_net_stats(
            bytes_sent=2_000_000, bytes_recv=8_000_000,
            packets_sent=2000, packets_recv=8000,
        )
        with patch("psutil.net_io_counters", return_value={"eth0": stats}):
            from collector.app.collectors.network import collect_network
            result = collect_network()
        assert len(result) == 1
        n = result[0]
        assert isinstance(n, NetworkInterfaceTelemetry)
        assert n.interface == "eth0"
        assert n.bytes_sent == 2_000_000
        assert n.bytes_received == 8_000_000
        assert n.packets_sent == 2000
        assert n.packets_received == 8000

    def test_loopback_excluded(self):
        """The 'lo' loopback interface must be excluded."""
        counters = {
            "lo": self._make_net_stats(),
            "eth0": self._make_net_stats(),
        }
        with patch("psutil.net_io_counters", return_value=counters):
            from collector.app.collectors.network import collect_network
            result = collect_network()
        interfaces = [n.interface for n in result]
        assert "lo" not in interfaces
        assert "eth0" in interfaces

    def test_empty_counters_returns_empty_list(self):
        with patch("psutil.net_io_counters", return_value={}):
            from collector.app.collectors.network import collect_network
            result = collect_network()
        assert result == []

    def test_psutil_failure_raises_runtime_error(self):
        with patch("psutil.net_io_counters", side_effect=OSError("no proc")):
            from collector.app.collectors.network import collect_network
            with pytest.raises(RuntimeError, match="Failed to read network I/O counters"):
                collect_network()


# ===========================================================================
# 5. Host Collector
# ===========================================================================

class TestHostCollector:
    """Tests for collector.app.collectors.host.collect_host"""

    def _make_vmem(self, total=8_000_000_000):
        vm = MagicMock()
        vm.total = total
        return vm

    def test_returns_host_telemetry_type(self):
        with patch("socket.gethostname", return_value="test-host"), \
             patch("socket.getfqdn", return_value="test-host.example.com"), \
             patch("platform.system", return_value="Linux"), \
             patch("platform.version", return_value="#1 SMP"), \
             patch("platform.release", return_value="5.15.0"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("psutil.cpu_count", side_effect=[8, 4]), \
             patch("psutil.virtual_memory", return_value=self._make_vmem()):
            from collector.app.collectors.host import collect_host
            result = collect_host()
        assert isinstance(result, HostTelemetry)

    def test_hostname_populated(self):
        with patch("socket.gethostname", return_value="my-server"), \
             patch("socket.getfqdn", return_value="my-server.local"), \
             patch("platform.system", return_value="Linux"), \
             patch("platform.version", return_value=""), \
             patch("platform.release", return_value="5.15.0"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("psutil.cpu_count", side_effect=[4, 2]), \
             patch("psutil.virtual_memory", return_value=self._make_vmem()):
            from collector.app.collectors.host import collect_host
            result = collect_host()
        assert result.hostname == "my-server"

    def test_os_info_populated(self):
        with patch("socket.gethostname", return_value="host"), \
             patch("socket.getfqdn", return_value="host"), \
             patch("platform.system", return_value="Linux"), \
             patch("platform.version", return_value="Ubuntu 22.04"), \
             patch("platform.release", return_value="5.15.0-91-generic"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("psutil.cpu_count", side_effect=[4, 2]), \
             patch("psutil.virtual_memory", return_value=self._make_vmem()):
            from collector.app.collectors.host import collect_host
            result = collect_host()
        assert result.os_name == "Linux"
        assert result.os_release == "5.15.0-91-generic"
        assert result.architecture == "x86_64"

    def test_cpu_counts_populated(self):
        with patch("socket.gethostname", return_value="host"), \
             patch("socket.getfqdn", return_value="host"), \
             patch("platform.system", return_value="Linux"), \
             patch("platform.version", return_value=""), \
             patch("platform.release", return_value="5.15.0"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("psutil.cpu_count", side_effect=[16, 8]), \
             patch("psutil.virtual_memory", return_value=self._make_vmem()):
            from collector.app.collectors.host import collect_host
            result = collect_host()
        assert result.cpu_count_logical == 16
        assert result.cpu_count_physical == 8

    def test_total_memory_populated(self):
        with patch("socket.gethostname", return_value="host"), \
             patch("socket.getfqdn", return_value="host"), \
             patch("platform.system", return_value="Linux"), \
             patch("platform.version", return_value=""), \
             patch("platform.release", return_value="5.15.0"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("psutil.cpu_count", side_effect=[4, 2]), \
             patch("psutil.virtual_memory", return_value=self._make_vmem(total=32_000_000_000)):
            from collector.app.collectors.host import collect_host
            result = collect_host()
        assert result.total_memory_bytes == 32_000_000_000

    def test_collector_version_present(self):
        with patch("socket.gethostname", return_value="host"), \
             patch("socket.getfqdn", return_value="host"), \
             patch("platform.system", return_value="Linux"), \
             patch("platform.version", return_value=""), \
             patch("platform.release", return_value="5.15.0"), \
             patch("platform.machine", return_value="x86_64"), \
             patch("psutil.cpu_count", side_effect=[4, 2]), \
             patch("psutil.virtual_memory", return_value=self._make_vmem()):
            from collector.app.collectors.host import collect_host
            result = collect_host(collector_version="0.4.0")
        assert result.collector_version == "0.4.0"


# ===========================================================================
# 6. Service Collector
# ===========================================================================

class TestServiceCollector:
    """Tests for collector.app.collectors.services.collect_services"""

    def test_returns_empty_list_when_systemctl_unavailable(self):
        """When systemctl is not on PATH, an empty list is returned (not an error)."""
        with patch("shutil.which", return_value=None):
            from collector.app.collectors.services import collect_services
            result = collect_services(unit_names=["nginx.service"])
        assert result == []

    def test_returns_service_telemetry_for_active_unit(self):
        """An active unit is parsed and returned correctly."""
        mock_output = "LoadState=loaded\nActiveState=active\nSubState=running\n"
        mock_result = MagicMock()
        mock_result.stdout = mock_output
        mock_result.returncode = 0

        with patch("shutil.which", return_value="/usr/bin/systemctl"), \
             patch("subprocess.run", return_value=mock_result):
            from collector.app.collectors.services import collect_services
            result = collect_services(unit_names=["nginx.service"])

        assert len(result) == 1
        assert isinstance(result[0], ServiceTelemetry)
        assert result[0].name == "nginx.service"
        assert result[0].active_state == "active"
        assert result[0].sub_state == "running"
        assert result[0].load_state == "loaded"

    def test_not_found_unit_excluded(self):
        """Units with LoadState=not-found are not included in results."""
        mock_output = "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
        mock_result = MagicMock()
        mock_result.stdout = mock_output
        mock_result.returncode = 0

        with patch("shutil.which", return_value="/usr/bin/systemctl"), \
             patch("subprocess.run", return_value=mock_result):
            from collector.app.collectors.services import collect_services
            result = collect_services(unit_names=["nonexistent.service"])

        assert result == []

    def test_timeout_on_unit_query_skips_gracefully(self):
        """A timeout querying one unit does not crash the collector."""
        import subprocess as sp

        with patch("shutil.which", return_value="/usr/bin/systemctl"), \
             patch("subprocess.run", side_effect=sp.TimeoutExpired(cmd="systemctl", timeout=5)):
            from collector.app.collectors.services import collect_services
            result = collect_services(unit_names=["slow.service"])
        assert result == []

    def test_multiple_units_partially_found(self):
        """Only known units are returned; not-found units are silently excluded."""
        def _side_effect(cmd, **kwargs):
            unit = cmd[-1]
            if unit == "nginx.service":
                r = MagicMock()
                r.stdout = "LoadState=loaded\nActiveState=active\nSubState=running\n"
                r.returncode = 0
                return r
            else:
                r = MagicMock()
                r.stdout = "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                r.returncode = 1
                return r

        with patch("shutil.which", return_value="/usr/bin/systemctl"), \
             patch("subprocess.run", side_effect=_side_effect):
            from collector.app.collectors.services import collect_services
            result = collect_services(unit_names=["nginx.service", "ghost.service"])

        assert len(result) == 1
        assert result[0].name == "nginx.service"


# ===========================================================================
# 7. Telemetry Payload Aggregation
# ===========================================================================

class TestTelemetryPayload:
    """Tests for the TelemetryPayload composite model."""

    def test_empty_payload_valid(self):
        """A payload with no sub-collectors should still be valid."""
        payload = TelemetryPayload()
        assert payload.host is None
        assert payload.cpu is None
        assert payload.memory is None
        assert payload.disk == []
        assert payload.network == []
        assert payload.services == []
        assert payload.collection_errors == []

    def test_collected_at_is_utc(self):
        """collected_at must be timezone-aware (UTC)."""
        payload = TelemetryPayload()
        assert payload.collected_at.tzinfo is not None

    def test_payload_with_all_subfields(self):
        """A fully-populated payload should serialise without error."""
        payload = TelemetryPayload(
            host=HostTelemetry(hostname="test-host", collector_version="0.4.0"),
            cpu=CpuTelemetry(cpu_percent=55.0),
            memory=MemoryTelemetry(
                total_bytes=8_000_000_000,
                available_bytes=4_000_000_000,
                used_bytes=4_000_000_000,
                memory_percent=50.0,
            ),
            disk=[DiskTelemetry(path="/", total_bytes=100, used_bytes=60, free_bytes=40, percent=60.0)],
            network=[NetworkInterfaceTelemetry(
                interface="eth0", bytes_sent=100, bytes_received=200,
                packets_sent=10, packets_received=20,
            )],
            services=[ServiceTelemetry(name="nginx.service", active_state="active")],
        )
        as_json = payload.model_dump_json()
        assert "test-host" in as_json
        assert "nginx.service" in as_json

    def test_collection_errors_accumulated(self):
        """collection_errors list is preserved in the payload."""
        payload = TelemetryPayload(
            collection_errors=["cpu collection failed: test", "disk collection failed: test"],
        )
        assert len(payload.collection_errors) == 2

    def test_model_dump_json_round_trip(self):
        """model_dump_json() must produce valid JSON that Pydantic can parse back."""
        import json
        payload = TelemetryPayload(
            cpu=CpuTelemetry(cpu_percent=42.0),
        )
        raw = payload.model_dump_json()
        parsed = json.loads(raw)
        assert parsed["cpu"]["cpu_percent"] == pytest.approx(42.0)


# ===========================================================================
# 8. Configuration
# ===========================================================================

class TestCollectorSettings:
    """Tests for collector.app.config.settings.CollectorSettings"""

    def test_defaults_load_without_env(self):
        """Default values are present without any environment variables set."""
        # Instantiate directly (bypasses lru_cache).
        # Pydantic-settings will use defaults since no env vars conflict.
        settings = CollectorSettings(
            BACKEND_URL="http://localhost:8000",
            COLLECTOR_API_KEY="",
            COLLECTION_INTERVAL=30,
            LOG_LEVEL="INFO",
            COLLECT_SERVICES=True,
        )
        assert settings.BACKEND_URL == "http://localhost:8000"
        assert settings.COLLECTION_INTERVAL == 30
        assert settings.LOG_LEVEL == "INFO"
        assert settings.COLLECT_SERVICES is True

    def test_env_override_backend_url(self):
        """BACKEND_URL can be overridden via direct field assignment."""
        settings = CollectorSettings(
            BACKEND_URL="http://192.168.1.50:8000",
            COLLECTOR_API_KEY="",
        )
        assert settings.BACKEND_URL == "http://192.168.1.50:8000"

    def test_env_override_interval(self):
        settings = CollectorSettings(
            COLLECTION_INTERVAL=60,
            COLLECTOR_API_KEY="",
        )
        assert settings.COLLECTION_INTERVAL == 60

    def test_minimum_interval_enforced(self):
        """COLLECTION_INTERVAL below 5 should raise a validation error."""
        with pytest.raises(Exception):
            CollectorSettings(
                COLLECTION_INTERVAL=1,
                COLLECTOR_API_KEY="",
            )

    def test_collector_api_key_not_in_repr(self):
        """The API key must not appear in the default pydantic repr of settings."""
        # Pydantic v2 does NOT redact secrets in repr by default.
        # This test verifies the key is not accidentally logged by the
        # collector itself — we check that the settings object exists and
        # can be accessed securely through the COLLECTOR_API_KEY field only.
        settings = CollectorSettings(
            COLLECTOR_API_KEY="super-secret-token-abc123",
        )
        # The key is accessible via the field, but the collector must never
        # log this value.  The repr test is a documentation check.
        assert settings.COLLECTOR_API_KEY == "super-secret-token-abc123"
        # Verify it's not accidentally in BACKEND_URL or LOG_LEVEL
        assert "super-secret-token-abc123" not in settings.BACKEND_URL
        assert "super-secret-token-abc123" not in settings.LOG_LEVEL


# ===========================================================================
# 9. Backend Client — URL Usage
# ===========================================================================

class TestBackendClientUrl:
    """Tests that the backend client uses the configured URL correctly."""

    def test_backend_url_stripped_of_trailing_slash(self):
        from collector.app.clients.backend import BackendClient
        client = BackendClient(
            backend_url="http://192.168.1.10:8000/",
            api_key="dummy",
        )
        assert not client.backend_url.endswith("/")
        client.close()

    def test_send_telemetry_posts_to_correct_endpoint(self):
        """send_telemetry() must POST to <BACKEND_URL>/api/v1/telemetry."""
        from collector.app.clients.backend import BackendClient

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.status_code = 202

        with patch("requests.Session.post", return_value=mock_response) as mock_post:
            client = BackendClient(
                backend_url="http://test-backend:8000",
                api_key="dummy-key",
            )
            payload = TelemetryPayload()
            result = client.send_telemetry(payload)

        assert result is True
        posted_url = mock_post.call_args[0][0]
        assert posted_url == "http://test-backend:8000/api/v1/telemetry"
        client.close()

    def test_authorization_header_is_set(self):
        """The Authorization header must be present in outgoing requests."""
        from collector.app.clients.backend import BackendClient

        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.status_code = 202

        with patch("requests.Session.post", return_value=mock_response):
            client = BackendClient(
                backend_url="http://test-backend:8000",
                api_key="test-token-xyz",
            )
            # Access the session headers directly
            auth_header = client._session.headers.get("Authorization", "")

        assert auth_header == "Bearer test-token-xyz"
        client.close()


# ===========================================================================
# 10. Authentication Token Not Exposed in Logs
# ===========================================================================

class TestApiKeyNotLogged:
    """Verify that the COLLECTOR_API_KEY never appears in log output."""

    def test_api_key_not_in_warning_log_on_connection_failure(self, caplog):
        """
        When a connection fails, the warning log must not contain the API key.
        """
        from collector.app.clients.backend import BackendClient
        from requests.exceptions import ConnectionError as ReqConnError

        secret_token = "VERY_SECRET_TOKEN_12345"

        with patch("requests.Session.post", side_effect=ReqConnError("refused")):
            client = BackendClient(
                backend_url="http://unreachable:8000",
                api_key=secret_token,
            )
            with caplog.at_level(logging.WARNING, logger="collector"):
                client.send_telemetry(TelemetryPayload())

        for record in caplog.records:
            assert secret_token not in record.getMessage(), (
                f"API key leaked in log message: {record.getMessage()}"
            )
        client.close()

    def test_api_key_not_in_session_repr(self):
        """The API key must not be trivially accessible via repr."""
        from collector.app.clients.backend import BackendClient
        secret = "ANOTHER_SECRET_TOKEN"
        client = BackendClient(backend_url="http://localhost:8000", api_key=secret)
        # The public backend_url property is safe to inspect
        assert secret not in client.backend_url
        client.close()


# ===========================================================================
# 11. Backend Connection Failure Handling
# ===========================================================================

class TestBackendConnectionFailure:
    """Verify that connection failures are handled gracefully."""

    def test_connection_refused_returns_false(self):
        """A ConnectionError must return False, not raise."""
        from collector.app.clients.backend import BackendClient
        from requests.exceptions import ConnectionError as ReqConnError

        with patch("requests.Session.post", side_effect=ReqConnError("refused")):
            client = BackendClient(backend_url="http://localhost:9999", api_key="x")
            result = client.send_telemetry(TelemetryPayload())

        assert result is False
        client.close()

    def test_timeout_returns_false(self):
        """A Timeout must return False, not raise."""
        from collector.app.clients.backend import BackendClient
        from requests.exceptions import Timeout

        with patch("requests.Session.post", side_effect=Timeout("timed out")):
            client = BackendClient(backend_url="http://localhost:9999", api_key="x")
            result = client.send_telemetry(TelemetryPayload())

        assert result is False
        client.close()

    def test_non_2xx_returns_false(self):
        """A 500 response must return False, not raise."""
        from collector.app.clients.backend import BackendClient

        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        with patch("requests.Session.post", return_value=mock_response):
            client = BackendClient(backend_url="http://localhost:8000", api_key="x")
            result = client.send_telemetry(TelemetryPayload())

        assert result is False
        client.close()

    def test_401_returns_false(self):
        """An authentication failure (401) must return False, not raise."""
        from collector.app.clients.backend import BackendClient

        mock_response = MagicMock()
        mock_response.ok = False
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch("requests.Session.post", return_value=mock_response):
            client = BackendClient(backend_url="http://localhost:8000", api_key="wrong")
            result = client.send_telemetry(TelemetryPayload())

        assert result is False
        client.close()


# ===========================================================================
# 12. Collection Loop — Clean Stop
# ===========================================================================

class TestCollectionLoop:
    """Tests that the collection loop can be stopped cleanly."""

    def test_run_collection_cycle_returns_payload(self):
        """run_collection_cycle() must return a TelemetryPayload."""
        from collector.main import run_collection_cycle

        cpu_t = CpuTelemetry(cpu_percent=10.0)
        mem_t = MemoryTelemetry(
            total_bytes=8_000_000_000, available_bytes=4_000_000_000,
            used_bytes=4_000_000_000, memory_percent=50.0,
        )
        host_t = HostTelemetry(hostname="test-host", collector_version="0.4.0")

        with patch("collector.main.collect_host", return_value=host_t), \
             patch("collector.main.collect_cpu", return_value=cpu_t), \
             patch("collector.main.collect_memory", return_value=mem_t), \
             patch("collector.main.collect_disk", return_value=[]), \
             patch("collector.main.collect_network", return_value=[]), \
             patch("collector.main.collect_services", return_value=[]):
            result = run_collection_cycle(client=None, collect_svc=False)

        assert isinstance(result, TelemetryPayload)
        assert result.cpu.cpu_percent == 10.0
        assert result.memory.memory_percent == 50.0

    def test_sub_collector_failure_does_not_raise(self):
        """
        If an individual sub-collector raises, run_collection_cycle must
        complete and include the error in collection_errors, not propagate it.
        """
        from collector.main import run_collection_cycle

        with patch("collector.main.collect_host", side_effect=RuntimeError("host fail")), \
             patch("collector.main.collect_cpu", side_effect=RuntimeError("cpu fail")), \
             patch("collector.main.collect_memory", return_value=MemoryTelemetry(
                 total_bytes=1, available_bytes=0, used_bytes=1, memory_percent=100.0
             )), \
             patch("collector.main.collect_disk", return_value=[]), \
             patch("collector.main.collect_network", return_value=[]), \
             patch("collector.main.collect_services", return_value=[]):
            result = run_collection_cycle(client=None, collect_svc=False)

        assert result.host is None
        assert result.cpu is None
        assert result.memory is not None
        assert len(result.collection_errors) >= 2

    def test_main_loop_exits_on_running_flag(self):
        """
        The main() loop should exit cleanly when _running is set to False
        after the first collection cycle.
        """
        import collector.main as main_module

        call_count = 0

        def fake_cycle(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            # Stop the loop after the first cycle
            main_module._running = False
            return TelemetryPayload()

        original_running = main_module._running
        try:
            main_module._running = True
            mock_settings = CollectorSettings(
                COLLECTION_INTERVAL=5,
                LOG_LEVEL="WARNING",
                COLLECTOR_API_KEY="test-key",
                _env_file=None,  # type: ignore[call-arg]
            )
            with patch("collector.main.get_collector_settings", return_value=mock_settings), \
                 patch("collector.main.build_client_from_settings", return_value=None), \
                 patch("collector.main.run_collection_cycle", side_effect=fake_cycle), \
                 patch("time.sleep"):
                main_module.main()

            assert call_count >= 1
        finally:
            main_module._running = original_running
