# OpsTrace: Linux Log Analyzer & Infrastructure Health Monitor

OpsTrace is an explainable, lightweight Linux infrastructure monitoring, log analysis, and incident correlation platform designed to help engineers investigate and triage infrastructure and application incidents with clarity.

---

## 1. The Problem OpsTrace Solves

When infrastructure or software incidents occur in production, engineering teams typically face three major challenges:
1. **Tooling Overhead:** Industry observability suites (e.g., full ELK stacks, distributed Kafka pipelines, or multi-tenant APM solutions) are resource-heavy, complex to maintain, and difficult to comprehend.
2. **Disjointed Context:** Telemetry metrics, raw application/system logs, and recent deployment or configuration changes reside in separate silos, making it difficult to answer: *"What broke, what changed immediately before it broke, and what is the blast radius?"*
3. **Risky or Uncontrolled Remediation:** Autonomous remediation agents can execute destructive actions, while purely manual remediation lacks audit trails.

OpsTrace addresses these issues through:
- **Lightweight host telemetry & raw log streaming** via a non-invasive Python daemon.
- **Centralized backend log parsing, fingerprinting, and error-rate tracking.**
- **Deterministic threshold and health evaluation** using multi-sample sustainment rules.
- **Change-aware correlation** that attributes candidate contributing changes while maintaining that *correlation does not prove causation*.
- **Dependency impact analysis** mapping the blast radius across dependent services.
- **Controlled remediation workflows** requiring explicit human approval and permanent audit logging (with zero risky remote shell execution in the MVP).

---

## 2. High-Level Architecture

```
+---------------------------+
|    Target Linux Host      |
|  - psutil & /proc reader  |
|  - Raw log tailer         |
+-------------+-------------+
              | HTTP/REST + Bearer Token
              v
+---------------------------+       +-----------------------------+
|    Nginx Reverse Proxy    | <---> | React + TypeScript Frontend |
+-------------+-------------+       +-----------------------------+
              |
              v
+---------------------------+       +-----------------------------+
|      FastAPI Backend      | <---> |     Prometheus & Grafana    |
| - Ingestion & Validation  |       |       (Self-Monitoring)     |
| - Log Analyzer            |       +-----------------------------+
| - Health Engine           |
| - Incident Engine         |
| - Change Correlation      |
| - Dependency DAG          |
| - Remediation Approval    |
+-------------+-------------+
              |
              v
+---------------------------+
|    PostgreSQL Database    |
| (Normalized Relational DB)|
+---------------------------+
```

### Core Architecture Components:
- **Collector (`collector/`):** Passive Linux daemon gathering CPU, memory, disk, network, systemd service states, and raw log lines.
- **Backend (`backend/`):** Modular FastAPI application managing ingestion, rule engines, correlation logic, and data access.
- **Frontend (`frontend/`):** React + TypeScript SPA providing fleet status, log streams, incident replays, and remediation review consoles.
- **Persistence (`PostgreSQL 16`):** Single source of truth for telemetry, logs, changes, incidents, and audit trails.
- **Gateway & Observability (`infra/`):** Nginx reverse proxy, Prometheus metrics scraper, and Grafana operational dashboards.

---

## 3. Technology Stack

- **Backend:** Python 3.11+, FastAPI, SQLAlchemy 2.0, Pydantic v2
- **Database:** PostgreSQL 16
- **Frontend:** React, TypeScript, Vite
- **Operating System / Target:** Linux / Ubuntu, Bash
- **Monitoring & Observability:** Prometheus, Grafana
- **Web Infrastructure:** Nginx
- **Containerization:** Docker, Docker Compose
- **Cloud Infrastructure:** AWS EC2
- **DevOps & CI/CD:** Git, GitHub Actions
- **Testing:** Pytest

---

## 4. Development Phases

The project is planned across 22 structured phases, implemented and verified in sequence:

- [x] **Phase 1:** Project architecture and repository setup
- [x] **Phase 2:** PostgreSQL database and schema
- [x] **Phase 3:** FastAPI backend foundation
- [x] **Phase 4:** Linux monitoring collector
- [x] **Phase 5:** Application/system log collection
- [x] **Phase 6:** Log analysis engine
- [x] **Phase 7:** Incident detection engine
- [x] **Phase 8:** Controlled remediation and audit
- [x] **Phase 9:** Change-aware correlation
- [x] **Phase 10:** Incident replay/timeline
- [x] **Phase 11:** Dependency and impact analysis
- [x] **Phase 12:** React dashboard
- [x] **Phase 13:** Prometheus integration
- [x] **Phase 14:** Grafana dashboards
- [x] **Phase 15:** Docker and Docker Compose
- [x] **Phase 16:** Nginx
- [x] **Phase 17:** GitHub Actions CI/CD
- [x] **Phase 18:** AWS EC2 deployment runbook (no AWS deployment performed)
- [x] **Phase 19:** Controlled failure simulation
- [x] **Phase 20:** Security audit
- [x] **Phase 21:** Testing and integration testing
- [ ] **Phase 22:** Documentation and interview preparation

## 5. Quick Start and Verification

### Configure and start

1. Install Docker Desktop or Docker Engine with the Compose plugin.
2. Copy `.env.example` to `.env` and replace the database password, collector API key, admin API key, and Grafana password with unique values. Keep `.env` private; Git ignores it. The backend safely encodes special characters when building its PostgreSQL URL.
3. From the repository root, run:

   ```sh
   docker compose config --quiet
   docker compose up -d --build
   docker compose ps
   ```

4. Open the dashboard at `http://localhost/`. Grafana is available at `http://localhost:3000/` from the host; its credentials are configured in `.env`. PostgreSQL and Prometheus remain private to the Compose network.

### Run tests

Run the backend suite in the backend container:

```sh
docker compose exec backend sh -c "python -m pytest /app/backend/tests -q"
```

Collector API tests assume the development/testing setting with no collector/admin keys. Clear the Compose-provided keys only for the test process:

```sh
docker compose exec backend sh -c "env -u ADMIN_API_KEY -u COLLECTOR_API_KEY ENVIRONMENT=testing python -m pytest /app/collector/tests -q"
```

For frontend checks, run `npm ci`, `npm test -- --run`, and `npm run build` from `frontend/` with Node.js installed.

### Architecture and verification status

The collector sends telemetry and logs to the FastAPI backend, which persists records in PostgreSQL and runs the analysis, incident, correlation, dependency, remediation, and timeline workflows. Prometheus scrapes backend metrics; Grafana visualizes them. Nginx serves the React dashboard and proxies API traffic. See [Architecture](docs/architecture.md) and [Docker deployment](docs/phase15-docker.md) for details.

Final local verification on 2026-10-06: all seven Compose services were running; backend and PostgreSQL health checks passed; Nginx served the dashboard and proxied its health route; Prometheus and Grafana health endpoints responded; the collector container could reach the backend. Backend tests passed (134), collector tests passed (341), and `docker compose config --quiet` passed. GitHub-hosted CI and AWS deployment were not run.

Phase 12 dashboard implementation and verification are complete. The frontend type check, production build, API client tests, backend suite, and collector suite pass. The backend HTTP suite required running outside the sandbox because Windows asyncio's local socket startup stalled inside it; see [Phase 12 dashboard status](docs/phase12-dashboard.md).

Phase 13 is implemented and verified. The collector submits its existing host, CPU, memory, disk, network, and systemd service snapshots to the backend. The backend persists numeric samples using the existing SQLAlchemy models and exposes operational metrics at `/metrics` for Prometheus scraping. See [Prometheus integration](docs/phase13-prometheus.md).

Phase 14 adds a provisioned Prometheus datasource and OpsTrace Grafana dashboard for host telemetry, services, incidents, and collector health. Its phase report records that live startup was not verified at that milestone; see [Grafana dashboard status](docs/phase14-grafana.md). The current live stack was checked in the final verification below.

Phase 15 adds container images for the backend, collector, and frontend, plus a Compose stack for PostgreSQL, Nginx, Prometheus, and Grafana. The phase report records its verification results at that milestone. Setup, ports, health checks, persistence, and the bundled collector's container-scope limitations are described in [Docker deployment](docs/phase15-docker.md).

Phase 16 configures the Nginx gateway for API and SPA routing, forwards health checks, applies proxy limits and security headers, and relies on the frontend server for immutable Vite asset caching. Prometheus stays private on the Compose network; Grafana is bound to the host loopback address. See [Nginx configuration](docs/phase16-nginx.md) for the phase's recorded validation.

Phase 17 adds GitHub Actions checks for backend and collector tests, frontend tests/type-check/build, configuration validation, Prometheus validation, and local-only builds of all four Docker images. The workflow uses read-only repository permissions, does not require application secrets, publish images, or deploy to AWS. GitHub-hosted execution has not been performed. See [CI/CD documentation](docs/phase17-cicd.md).

Phase 19 adds a fixture-only failure simulation API that routes synthetic events through the existing log analyzer, incident detector, dry-run remediation planner, and (for dependency failures) the dependency engine using a per-run in-memory graph. The simulations do not access configured databases, host services, or AWS. Phase 19 verification at the time passed 340 collector tests, 119 backend tests, and 11 focused Phase 19 tests. Docker was unavailable, and no AWS resources were used. See [controlled failure simulation](docs/phase19-failure-simulation.md).

Phase 20 hardens production API-key configuration, secret serialization, CORS, request validation, database URL construction, exception handling, collector logging, and container privileges. The collector suite passed 341 tests; the backend suite passed 133 tests, including 14 backend security tests; static configuration validation also passed. Docker and dependency advisory scanners are unavailable here; no AWS resources were used. Unauthenticated dashboard reads and the HTTP-only gateway remain documented production limitations. See [Security audit](docs/phase20-security-audit.md). Next is Phase 21 — Testing and integration.

Phase 21 adds a persisted collector-to-backend incident workflow covering authenticated telemetry/log ingestion, analysis, incident persistence, deployment/config correlation, dependency impact, dry-run remediation/audit, timeline, and read-only replay. Verification passed 341 collector tests, 134 backend tests, 4 frontend API tests, frontend TypeScript/build, and static Compose/Nginx/Prometheus/Grafana/workflow validation (479 tests total, zero failures). The Phase 21 milestone report notes Docker was unavailable at that time; live services have since been checked below. Dependency advisory scanning, GitHub-hosted CI, and AWS deployment were not performed. See [Testing and integration](docs/phase21-testing-integration.md). Next is Phase 22 — Documentation and interview preparation.

Phase 18 documents a single-EC2 deployment using the existing Docker Compose stack, with restricted security group rules, loopback-only Grafana access, persistent volumes, backups, health checks, and safe update/rollback steps. Local validation passed: 448 backend/collector tests, 4 frontend tests, frontend build, and configuration/workflow static checks. No AWS resources were created and no EC2 deployment was performed. The current Nginx gateway has no TLS listener, so the documented HTTP setup is for a non-sensitive lab/demo only until HTTPS termination is configured. See [AWS EC2 deployment](docs/phase18-aws-ec2.md).

---

## Incident Timeline & Replay (Phase 10)

OpsTrace provides an observation and reconstruction layer that reconstructs the complete chronological lifecycle of an operational incident from stored database events.

### Key Concepts:
- **Incident Timeline:** Combines detection events, severity escalations, candidate deployments/config changes (Phase 9), and remediation records (Phase 8) into a single deterministically sorted chronological timeline.
- **Incident Replay:** A strictly read-only, step-by-step reconstruction of incident state over time. Replay does NOT execute shell commands, deployments, or database modifications.
- **Non-Causal Guarantee:** Preserves the explicit rule that candidate change correlation indicates temporal/spatial proximity and does NOT prove causation.

### REST Endpoints:
- `GET /api/v1/incidents/{incident_id}/timeline`: Full chronological timeline.
- `GET /api/v1/incidents/{incident_id}/replay`: Step-by-step state reconstruction snapshots.
- `GET /api/v1/incidents/{incident_id}/timeline/summary`: Compact timeline summary with severity transitions and candidate changes.

