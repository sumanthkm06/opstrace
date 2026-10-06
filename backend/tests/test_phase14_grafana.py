"""Static checks for the provisioned Phase 14 Grafana dashboard."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_has_required_operational_panels_and_metrics():
    dashboard = json.loads(
        (ROOT / "infra/grafana/dashboards/opstrace-infrastructure.json").read_text()
    )
    panels = dashboard["panels"]
    titles = {panel["title"] for panel in panels}
    queries = "\n".join(
        target["expr"] for panel in panels for target in panel.get("targets", [])
    )

    assert dashboard["uid"] == "opstrace-infrastructure"
    assert len(panels) >= 8
    assert {
        "CPU Utilization",
        "Memory Utilization",
        "Disk Utilization",
        "Network Throughput",
        "Service Availability",
        "Active Incidents by Severity",
    } <= titles
    assert "opstrace_host_cpu_usage_percent" in queries
    assert "opstrace_host_memory_usage_percent" in queries
    assert "opstrace_host_disk_usage_percent" in queries
    assert "opstrace_host_network_bytes_total" in queries
    assert "opstrace_service_up" in queries
    assert "opstrace_incidents" in queries
    assert all(panel.get("description") for panel in panels)
    assert all(panel["datasource"]["uid"] == "opstrace-prometheus" for panel in panels)


def test_datasource_and_dashboard_provisioning_match_compose_mounts():
    datasource = (ROOT / "infra/grafana/provisioning/datasources/prometheus.yml").read_text()
    provider = (ROOT / "infra/grafana/provisioning/dashboards/opstrace.yml").read_text()
    compose = (ROOT / "docker-compose.yml").read_text()

    assert "uid: opstrace-prometheus" in datasource
    assert "url: http://prometheus:9090" in datasource
    assert "path: /var/lib/grafana/dashboards" in provider
    assert "./infra/grafana/provisioning:/etc/grafana/provisioning:ro" in compose
    assert "./infra/grafana/dashboards:/var/lib/grafana/dashboards:ro" in compose
