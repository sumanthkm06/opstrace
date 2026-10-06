# Phase 20 — Security Audit

## 1. Security objectives

Apply practical security controls without changing OpsTrace's service architecture. This audit covers the checked-in backend, collector, frontend, Docker Compose stack, Nginx, Prometheus/Grafana provisioning, CI workflow, and deployment documentation. It does not certify the system as fully secure.

## 2. Threat model and findings

The relevant threats are unauthenticated writes/collection, credential exposure, operational data disclosure, malformed or oversized requests, unsafe command/file access, and an internet-facing HTTP-only demo deployment.

| Severity | Finding | Status |
| --- | --- | --- |
| High | Protected collector API routes skipped authentication when the key was unset, including in production. | Fixed: production settings reject absent/template/short keys and protected routes fail closed. |
| High | Dashboard resource and dependency reads, liveness/readiness, and Prometheus metrics are not user-authenticated. | Known limitation: retained for current dashboard/monitoring behavior; see production recommendations. |
| Medium | The correlation write endpoint used the shared collector key and returned raw exception text. | Fixed: write requires `ADMIN_API_KEY`; responses and logs no longer include exception contents. |
| Medium | Database settings had a predictable password fallback and interpolated credentials directly into a URL. | Fixed: no default password; SQLAlchemy URL construction safely encodes credentials. |
| Medium | CORS used `*` in development and testing. | Fixed: explicit origins are used in all environments; production rejects wildcard configuration. |
| Medium | Backend and collector images ran as root and had default Linux capabilities. | Fixed: images use a dedicated unprivileged UID; Compose drops capabilities and prevents privilege escalation. |
| Low | Log ingestion accepted unknown fields and unbounded event batches/messages. | Fixed: unknown fields are rejected, batches cap at 1,000 events, and messages cap at 16 KiB. |
| Low | Collector logged arbitrary response bodies from a failed backend request. | Fixed: rejection logs retain only status and backend URL, omitting response content. |
| Low | Prometheus lifecycle reload was enabled without authentication on the internal network. | Fixed: lifecycle reload is disabled. |

## 3. API security and authentication

Collector ingestion, telemetry, analysis, incident timeline/replay, and correlation-read routes use bearer authentication when configured. `COLLECTOR_API_KEY` is compared with constant-time comparison. In production, a missing or template key is a configuration error; protected requests fail closed. Missing keys remain an intentional local-development/testing convenience only.

The correlation write operation and failure simulation endpoint use `ADMIN_API_KEY`. The latter remains fixture-only and dry-run. `GET /health` is an unauthenticated liveness probe for container/load-balancer health checks. `GET /api/v1/health` is an unauthenticated readiness probe. `/metrics` is intentionally outside `/api/v1` for Prometheus scraping and is only published on the Compose network.

Dashboard resource endpoints (`/hosts`, `/services`, `/incidents`, `/remediations`, and dependency analysis) remain unauthenticated so the existing browser dashboard continues to work. They expose operational details and should be placed behind an authenticated identity-aware gateway or private network before use with sensitive or public workloads. Current same-origin Nginx is not an authentication boundary.

## 4. Input validation

Simulation requests reject unknown fields and accept only predefined scenarios. They do not expose command or file-path parameters. Correlation request bodies reject extra fields and range-check their scoring/window values. Log ingestion rejects unknown body/event properties, limits each request to 1,000 events and each message to 16 KiB, and limits the count of collection errors. UUID paths are parsed as UUIDs. Dependency traversal depth is limited to 1–10. SQLAlchemy ORM expressions bind query values; the only raw database statement found is the fixed `SELECT 1` health probe.

Log `source` values are stored as descriptive data; no API maps that field to a file open. File paths in the collector are operator configuration (`LOG_FILE_PATHS`), not request input. No upload or arbitrary file-read endpoint exists.

## 5. Command execution

No `shell=True`, `os.system`, `eval`, or dynamic `exec` is present in runtime source. The collector uses `subprocess.run` only for read-only `journalctl` and `systemctl show`, with argument arrays, fixed executable names, and timeouts. Unit names are a built-in allowlist; log content is not passed as command arguments. Phase 8 remediation continues to select actions from `RemediationActionType`; Phase 19 simulations use synthetic fixtures and cannot invoke commands.

## 6. Secret management

No live credentials or private keys were found in the checked-in source/configuration scan. `.env.example` contains visibly fake placeholders. `.gitignore` excludes `.env` variants (except the template), common credential/private-key formats and directories, and added `.envrc`, `secrets/`, `*.secret`, and `*.credentials` patterns.

The backend no longer supplies a database password fallback. Production settings require non-placeholder credentials of at least 32 characters for the collector/admin keys and database password (unless a full `DATABASE_URL` is configured). Settings serialization omits secret fields and the computed database URL. Compose requires database, collector/admin, and Grafana password variables; operators must replace every template value before deployment.

## 7. File-system and database security

There are no user-controlled filesystem paths on backend APIs. Collector file logging reads only configured paths and does not write to them. ORM access is parameterized. Database health failures log only the exception type; generic API errors do not include internal exception text. SQLAlchemy URL creation encodes reserved characters in passwords. Production database users should be scoped to only the required database and schema operations.

## 8. CORS

`CORS_ALLOWED_ORIGINS` is a comma-separated exact-origin setting with local development origins as its default. Wildcard origins are rejected for `ENVIRONMENT=production`; credentials remain disabled. The same-origin Nginx layout does not require CORS. Production operators should set only the exact trusted browser origins or an empty list for same-origin access.

## 9. Nginx and network exposure

The gateway retains the two-tier Nginx design, applies `nosniff`, frame, referrer, and permissions headers, hides the Nginx version, limits request bodies to 10 MiB, and configures proxy timeouts/forwarded headers. Compose publishes only the gateway and binds Grafana to host loopback. PostgreSQL, backend, collector, and Prometheus have no published host ports; Prometheus is only on the Compose network.

The current gateway serves HTTP only. HSTS is therefore not enabled. Do not send real bearer keys or sensitive logs across a public HTTP connection; terminate TLS at a trusted edge before public deployment.

## 10. Docker security

Backend and collector images create and use UID/GID 10001. Compose applies `no-new-privileges`, drops all capabilities, and sets process limits for both. No service is privileged or uses host networking. Persistent data volumes are limited to PostgreSQL, Prometheus, and Grafana. Grafana remains loopback-bound with a required environment-supplied password. Prometheus lifecycle reload is disabled.

Static inspection was performed. Docker is not installed in this environment, so Compose parsing, image builds, and runtime privilege behavior were not verified here. Base image tags are versioned but not digest-pinned; image provenance/signature policy remains future hardening.

## 11. Prometheus and Grafana

Prometheus has no host port and scrapes only `backend:8000` on the private Compose network. Metrics do not include bearer credentials. Grafana's datasource uses the internal Prometheus address; the Grafana port binds to `127.0.0.1`. The admin username defaults to `admin`, but the password has no source-code default and Compose requires `GRAFANA_ADMIN_PASSWORD`. Keep Grafana behind an SSH tunnel/private access path.

## 12. GitHub Actions

The CI workflow requests only `contents: read`, has no deploy job or AWS credentials, and does not print secrets. Pull requests execute test/build/configuration checks but do not publish or deploy artifacts. Actions are referenced by the existing major-version tags; commit-SHA pinning is recommended for a higher-assurance supply-chain posture.

## 13. AWS / EC2

No AWS resources or commands were used. Phase 18's runbook calls for restricted SSH source ranges, only gateway HTTP/HTTPS ingress, no public database/Prometheus/backend/collector ports, loopback Grafana access, environment-held credentials, and encrypted storage. It explicitly notes that the current deployment has no TLS listener and must not carry sensitive traffic over public HTTP.

## 14. Dependency security

Python requirements use bounded major-version ranges rather than a fully hashed lock file; the frontend has a lock file and installs via `npm ci`. No obviously unnecessary dependency was identified during static review. `pip-audit` is not installed, and no online Python or npm advisory scan was run, so dependency CVE status is **not verified**. No dependency versions were changed in this audit.

## 15. Security tests and validation

`backend/tests/test_phase20_security.py` covers missing/invalid collector keys, production fail-closed behavior, admin-key protection of simulation, placeholder production credentials, safe database URL encoding, secret-safe settings serialization, malformed/extra/oversized requests, invalid remediation actions, absence of subprocess execution in simulations, sanitized correlation failures, explicit CORS, route exposure, and path-like log labels.

Verification: `python -m pytest collector/tests/ -v --tb=short` passed (341 tests, including the collector response-log security test); `python -m pytest backend/tests/ -v --tb=short` passed (133 tests, including 14 focused Phase 20 security tests); `python scripts/validate_ci_config.py` passed. Frontend source is unchanged; frontend tests/build were not rerun for this phase. Docker runtime validation is unavailable. AWS was not used.

## 16. Known limitations

- Dashboard resource and dependency endpoints are unauthenticated to preserve the existing frontend; they expose operational data.
- Health and Prometheus endpoints are unauthenticated by design and rely on network placement.
- The public gateway is HTTP-only; TLS termination remains an operator deployment requirement.
- Compose injects credentials through environment variables; Docker secrets or a cloud secret manager would reduce exposure through container inspection.
- Collector log-file access depends on operator-configured paths and filesystem permissions.
- The collector supports HTTP backend URLs; remote deployments must configure HTTPS to protect bearer keys in transit.
- Python dependency advisories, image digest provenance, live Docker behavior, and deployed AWS network policy were not verified here.

## 17. Recommended production improvements (not implemented or verified)

1. Add an identity-aware gateway/session layer for dashboard and resource APIs before exposing them outside a trusted private network.
2. Terminate TLS and enforce HTTPS before sending credentials or sensitive logs.
3. Use a secret manager or Docker secrets and rotate all generated keys/passwords.
4. Pin CI actions and container images by digest; scan dependencies and images on a scheduled cadence.
5. Run a deployment-specific threat review, verify EC2 security groups and encrypted backups, and test restore/rotation procedures.
6. Add API rate limits and pagination for high-volume resource endpoints if the service is exposed to broader clients.
