# Phase 13 — Prometheus Integration

## Data flow

1. The existing collector samples CPU, memory, disk, network, and systemd service state.
2. It posts each snapshot to `POST /api/v1/telemetry` using the existing backend client and collector bearer token.
3. The backend updates the existing `Host` and `Service` records and appends numeric samples to the existing `Metric` table.
4. The backend publishes the latest snapshot at `GET /metrics` in Prometheus text exposition format.
5. The existing Prometheus Compose service scrapes `backend:8000/metrics` every 15 seconds using `infra/prometheus/prometheus.yml`.

## Exported series

- `opstrace_telemetry_batches_received_total`
- `opstrace_collector_collection_errors_total{hostname}`
- `opstrace_host_cpu_usage_percent{hostname}`
- `opstrace_host_memory_usage_percent{hostname}`
- `opstrace_host_memory_used_bytes{hostname}`
- `opstrace_host_disk_usage_percent{hostname,mountpoint}`
- `opstrace_host_disk_free_bytes{hostname,mountpoint}`
- `opstrace_host_network_bytes_total{hostname,interface,direction}`
- `opstrace_service_up{hostname,service}`
- `opstrace_incidents{status,severity}`

Network byte series are counters that account for interface counter resets. Other sampled values are gauges. The current incident count series is refreshed from the existing incidents table during a scrape. The backend retains every numeric telemetry snapshot in its existing metrics table; Prometheus retains scrape history according to its own storage configuration.

## Configuration and verification

- `PROMETHEUS_METRICS_ENABLED` controls whether `/metrics` is registered. It defaults to enabled and is passed into the backend Compose service.
- Collector authentication follows the existing `COLLECTOR_API_KEY` behavior: required when configured, disabled in development when unset.
- Prometheus stays on the internal Compose network; no host port is published by this phase.
- Tests: backend 106 passed, collector 340 passed, frontend API client 4 passed; frontend TypeScript check and production build passed.
