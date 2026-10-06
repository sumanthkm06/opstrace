# Phase 16 — Nginx production configuration

## Role and Compose integration

The `nginx` service is the public HTTP gateway. It is the only application service published on the web port (`HTTP_PORT`, default `80`). It routes traffic to the internal `frontend` and `backend` services on the Compose network. Neither service publishes its own port.

Prometheus stays internal and scrapes `backend:8000/metrics` directly. Grafana is not routed through Nginx; its existing host port is bound to `127.0.0.1` so it remains available locally without listening on external interfaces. PostgreSQL remains private with no host port.

The gateway image copies `infra/nginx/nginx.conf` and its shared proxy header include. The frontend image has a separate Nginx instance that serves the compiled Vite output. This keeps API routing at the gateway and static file delivery in the frontend container.

## Request routing

- `/api/...` is proxied to `backend:8000` with the original request URI, method, body, and request headers. FastAPI response status and body are passed through; Nginx does not replace API errors with a generic error page.
- `/health` is proxied to the existing backend readiness endpoint at `/api/v1/health`. The API's native `/api/v1/health` route also remains available through the `/api/` proxy.
- All other paths go to `frontend:80`. The frontend Nginx serves built files and falls back to `/index.html` for client-side React Router routes. Missing versioned assets return 404 instead of the SPA document.

## Proxy and security settings

The gateway forwards the original host, client IP, proxy chain, scheme, host, and port. Upstream connections use HTTP/1.1 with connection reuse. Connect timeouts are five seconds; send and read timeouts are 60 seconds. The request body limit is 10 MiB, suitable for the current JSON telemetry and log ingestion endpoints.

Responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, a strict-origin referrer policy, and a restrictive permissions policy. `server_tokens` is disabled. A Content Security Policy is omitted because the existing frontend has not been audited for a safe policy. HSTS is omitted because this Compose gateway currently serves HTTP and does not terminate TLS.

Gzip is enabled for text, CSS, JSON, JavaScript, XML, and SVG responses. The frontend server marks the Vite `/assets/` files immutable for one year; these names are content-hashed by the production build. `index.html` is marked `no-cache` so deployments can discover new asset names.

## Validation and limitations

- Backend and collector suites: 448 passed.
- Frontend tests: 4 passed.
- Frontend TypeScript check and production build: passed.
- Compose YAML and service topology: statically parsed; Prometheus and Grafana config YAML also parsed.
- Nginx configuration: statically inspected, including route precedence, URI preservation, forwarding headers, size/time limits, response handling, and asset cache rules.
- Live `nginx -t`, Docker image builds, and `docker compose config` could not be run because neither Nginx nor Docker/Compose is installed in this environment.

The HTTP gateway has no TLS listener or certificate configuration. TLS termination and broader hardening can be added when the deployment environment and certificate strategy are defined.
