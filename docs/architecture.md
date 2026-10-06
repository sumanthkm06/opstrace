# OpsTrace Architecture Reference

This directory maintains architecture specifications, component designs, and operational runbooks for OpsTrace.

## Key Design Principles:
1. **Explainable and Deterministic:** All log parsing, thresholding, change correlation, and impact analysis follow transparent, rule-based algorithms.
2. **Modular Monolith Backend:** Single FastAPI service handling ingestion, business engines, and REST endpoints.
3. **Passive Linux Collector:** Minimal footprint Python daemon streaming raw telemetry and unparsed logs.
4. **Controlled Remediation:** Recommendations require human operator approval with full audit tracking. Zero remote shell execution.
5. **Relational Consistency:** PostgreSQL 16 normalized schema with ACID guarantees and indexed time-series queries.

## Prometheus Metrics (Phase 13)

The Linux collector continues to own infrastructure collection and posts its existing telemetry snapshots to `POST /api/v1/telemetry`. The backend updates host and service state and stores numeric samples in the existing `metrics` table. Prometheus scrapes the backend's `/metrics` endpoint; the scrape endpoint exports the newest in-process host gauges and cumulative network counters. The Prometheus scrape target is configured in `infra/prometheus/prometheus.yml`.

Collector ingestion uses the existing bearer-token setting when `COLLECTOR_API_KEY` is configured. Prometheus is expected to reach `/metrics` over the internal Compose network. The scrape endpoint can be disabled with `PROMETHEUS_METRICS_ENABLED=false`.

## Grafana Dashboards (Phase 14)

Grafana provisions the Prometheus datasource and the OpsTrace Infrastructure & Incidents dashboard from files under `infra/grafana/`. The dashboard queries the existing host/service/collector series and the current incident count series from `/metrics`; it does not introduce another metrics store or collection path. Docker Compose mounts the provisioning and dashboard files read-only into Grafana.
