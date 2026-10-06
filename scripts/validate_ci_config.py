"""Static checks for OpsTrace Compose and observability configuration."""

from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_yaml(path: Path) -> dict:
    """Parse YAML while treating YAML 1.1 boolean-like keys as strings."""
    with path.open(encoding="utf-8") as source:
        result = yaml.load(source, Loader=yaml.BaseLoader)
    if not isinstance(result, dict):
        raise ValueError(f"Expected a YAML mapping in {path.relative_to(ROOT)}")
    return result


def main() -> None:
    compose_path = ROOT / "docker-compose.yml"
    compose = load_yaml(compose_path)
    services = compose.get("services", {})
    required_services = {
        "database",
        "backend",
        "collector",
        "frontend",
        "nginx",
        "prometheus",
        "grafana",
    }
    missing_services = required_services - services.keys()
    if missing_services:
        raise ValueError(f"Compose services missing: {', '.join(sorted(missing_services))}")

    for private_service in ("database", "backend", "collector", "frontend", "prometheus"):
        if services[private_service].get("ports"):
            raise ValueError(f"Compose service {private_service} must not publish host ports")

    grafana_ports = services["grafana"].get("ports", [])
    if not grafana_ports or not grafana_ports[0].startswith("127.0.0.1:"):
        raise ValueError("Grafana must remain bound to the host loopback address")

    prometheus_path = ROOT / "infra/prometheus/prometheus.yml"
    prometheus = load_yaml(prometheus_path)
    targets = [
        target
        for scrape_config in prometheus.get("scrape_configs", [])
        for static_config in scrape_config.get("static_configs", [])
        for target in static_config.get("targets", [])
    ]
    if "backend:8000" not in targets:
        raise ValueError("Prometheus must scrape the backend on the internal Compose network")

    datasource = load_yaml(ROOT / "infra/grafana/provisioning/datasources/prometheus.yml")
    datasources = datasource.get("datasources", [])
    if not any(item.get("url") == "http://prometheus:9090" for item in datasources):
        raise ValueError("Grafana datasource must use the internal Prometheus service")

    dashboard_provisioning = load_yaml(
        ROOT / "infra/grafana/provisioning/dashboards/opstrace.yml"
    )
    if not dashboard_provisioning.get("providers"):
        raise ValueError("Grafana dashboard provisioning must define at least one provider")

    dashboard_path = ROOT / "infra/grafana/dashboards/opstrace-infrastructure.json"
    with dashboard_path.open(encoding="utf-8") as source:
        dashboard = json.load(source)
    if not dashboard.get("title") or not isinstance(dashboard.get("panels"), list):
        raise ValueError("Grafana dashboard JSON must include a title and panels list")

    workflow_paths = sorted((ROOT / ".github/workflows").glob("*.yml"))
    if not workflow_paths:
        raise ValueError("No GitHub Actions workflow YAML files found")
    for workflow_path in workflow_paths:
        load_yaml(workflow_path)

    # Static gateway contract checks. Docker/Nginx binaries are not needed to
    # catch accidental route, header, and exposure regressions here.
    nginx_path = ROOT / "infra/nginx/nginx.conf"
    nginx = nginx_path.read_text(encoding="utf-8")
    for directive in (
        "server_tokens off;",
        'add_header X-Content-Type-Options "nosniff" always;',
        'add_header X-Frame-Options "SAMEORIGIN" always;',
        'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
        "client_max_body_size 10m;",
        "location = /health",
        "proxy_pass http://backend:8000/api/v1/health;",
        "location ^~ /api/",
        "proxy_pass http://backend:8000;",
        "location /",
        "proxy_pass http://frontend:80;",
    ):
        if directive not in nginx:
            raise ValueError(f"Nginx gateway contract missing: {directive}")
    if "listen 443" in nginx or "Strict-Transport-Security" in nginx:
        raise ValueError("HTTP-only gateway must not claim TLS/HSTS is configured")

    print("Compose exposure, Nginx routing/security headers, Prometheus, Grafana, and workflow YAML static checks passed.")


if __name__ == "__main__":
    main()
