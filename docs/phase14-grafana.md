# Phase 14 — Grafana Dashboards

## Starting state

The repository already had a Grafana Compose service and persistent data volume, but `infra/grafana/` contained only a placeholder. There was no provisioned Prometheus datasource or dashboard. Existing Prometheus series covered host CPU/memory/disk/network, service availability, and collector batch/error activity. Incident counts were not exported.

## Implemented

- Grafana now loads datasource and dashboard provisioning files from read-only Compose mounts.
- The default datasource is the existing Prometheus service at `http://prometheus:9090` on the internal Compose network.
- Added the provisioned **OpsTrace Infrastructure & Incidents** dashboard with host selection and 10 described panels:
  - CPU utilization
  - Memory utilization and used bytes
  - Disk utilization and free space
  - Network throughput from cumulative byte counters
  - Service availability
  - Current open/investigating/mitigated incident counts by severity
  - Collector batch and error rates
- The backend scrape endpoint now refreshes `opstrace_incidents{status,severity}` from the existing incident table. This is read-only and does not change database schema or incident state.
- Remediation, detection, correlation, and timeline behavior are unchanged.

## Verification

- Phase 14 targeted tests: 3 passed.
- Full backend suite: 108 passed.
- Full collector suite: 340 passed.
- Frontend: 4 API tests passed; TypeScript check and production build remain passing from Phase 13. No frontend files changed in Phase 14.
- Dashboard JSON parses successfully; Docker Compose, Prometheus, Grafana datasource, and dashboard provider YAML files parse successfully.
- Docker/Grafana were not available in this environment, so container startup, datasource health, PromQL evaluation inside Prometheus, and rendered dashboard appearance were not verified live.
- The existing Compose file references `backend/Dockerfile` and `infra/nginx/Dockerfile`, which are not present yet. Container build/run wiring belongs to Phase 15.

## Next phase

Phase 15 — Docker and Docker Compose.
