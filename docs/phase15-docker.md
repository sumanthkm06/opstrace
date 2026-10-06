# Phase 15 — Docker and Docker Compose

Phase 15 packages the existing application components and runs them on one private Compose bridge network. PostgreSQL, Prometheus, and Grafana keep their data in named volumes. Nginx publishes the web application and forwards `/api/` traffic to FastAPI. Prometheus scrapes the backend directly over the internal network.

## Start the stack

1. Install Docker Engine or Docker Desktop with the Docker Compose plugin.
2. Copy `.env.example` to `.env` and replace the database password, collector key, admin key, and Grafana password with unique values. The backend safely URL-encodes special characters in the database password when constructing its SQLAlchemy URL. Keep `.env` private; it is ignored by Git.
3. From the repository root, run `docker compose up --build -d`.
4. Open `http://localhost/` for OpsTrace and `http://localhost:3000/` for Grafana. Grafana credentials come from `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD` in `.env`.
5. View service state with `docker compose ps` and logs with `docker compose logs -f backend collector`.

Set `HTTP_PORT` or `GRAFANA_PORT` in `.env` to change published host ports. PostgreSQL and Prometheus are not published to the host. The backend and collector communicate over the Compose network; no backend host port is published. The backend applies the existing Alembic migrations at startup after PostgreSQL is healthy.

The `postgres_data`, `prometheus_data`, and `grafana_data` named volumes retain state across container recreation. `docker compose down` preserves these volumes. Removing volumes deletes their data.

## Health and collector scope

PostgreSQL uses `pg_isready`; the backend readiness check verifies the database connection; the frontend checks its local HTTP server; and Nginx checks its proxied health endpoint. Backend startup waits for a healthy database, while the collector, gateway, and Prometheus wait for their dependencies to become healthy.

The Compose collector is a containerized example agent. It reports the container's visible system metrics, and disables systemd and log collection because the container has no host systemd journal or host log mounts. It does not represent the Docker host's full hardware, services, or logs. For host monitoring, install and run the Linux collector directly on the monitored host with `BACKEND_URL` set to a reachable OpsTrace API address and the matching `COLLECTOR_API_KEY`.

## Services and files

- `backend/Dockerfile` packages FastAPI and the shared collector modules used by backend analysis.
- `collector/Dockerfile` runs the existing collector daemon.
- `frontend/Dockerfile` builds the Vite app and serves the static SPA from Nginx.
- `infra/nginx/` contains the minimal gateway configuration needed by this Compose stack; advanced production Nginx hardening and tuning are Phase 16.
- Prometheus and Grafana retain their Phase 13/14 configuration and provisioning.

## Verification status

Validation passed: 448 backend and collector tests, 4 frontend tests, and the frontend TypeScript check/production build. The Compose document parses as YAML and contains the expected seven services and three named data volumes. Docker image builds and live Compose health checks require Docker and could not be run in the current environment because the Docker CLI is unavailable.
