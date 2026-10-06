# Phase 17 — GitHub Actions CI/CD

## CI architecture

The workflow at `.github/workflows/ci.yml` runs independent checks on GitHub-hosted Ubuntu runners. A push to any branch, a pull request, or a manual `workflow_dispatch` starts the workflow. Each job reports its own result, and a failing test, configuration check, or image build makes that job fail. The workflow uses repository read-only permissions and cancels an older run when a newer run starts for the same ref.

## Jobs and runtimes

- **Backend tests:** Python 3.11, backend and shared collector requirements, and `backend/tests`. The backend imports collector modules directly.
- **Collector tests:** Python 3.11, collector and backend requirements, and `collector/tests`. Existing integration tests exercise FastAPI and SQLAlchemy code from the backend.
- **Frontend tests and build:** Node.js 22, `npm ci` using `frontend/package-lock.json`, Vitest, and `npm run build` (which includes the existing TypeScript check).
- **Configuration validation:** PyYAML parses the Compose, Prometheus, Grafana provisioning, and workflow YAML. `scripts/validate_ci_config.py` checks expected internal service targets, loopback-only Grafana binding, and the Grafana dashboard JSON structure.
- **Docker and Compose validation:** GitHub-hosted Ubuntu's Docker engine runs `docker compose config --no-interpolate --quiet` without resolving any required secret values, validates Prometheus with `promtool`, and builds the backend, collector, frontend, and gateway images.

Docker images are tagged locally with `:ci` and are neither pushed nor deployed. No AWS deployment or cloud credentials are part of Phase 17.

## Secrets and permissions

CI does not need application, database, Grafana, registry, or cloud credentials. The workflow defines no secret values and requires no GitHub Actions secrets. The Compose check explicitly avoids interpolation so required runtime variables are not supplied with dummy secret values. Its workflow token has only `contents: read` permission.

## Branch and pull request behavior

All branch pushes and pull requests run the same checks, including pull requests from forks. There are no write permissions or deployment steps. GitHub branch protection is configured in repository settings separately; when desired, require the workflow's job checks before merging.

To investigate a failure, open the repository's **Actions** tab, select the failed **OpsTrace CI** run, and expand the failed job and step. Test output, configuration diagnostics, and Docker build errors are printed in the corresponding step logs.

## Validation status

The workflow was statically parsed locally, and its Python configuration validator was run locally. The backend and collector suites passed (448 tests), frontend tests passed (4 tests), and the frontend TypeScript check and production build passed. GitHub-hosted execution was not performed from this environment. Docker is not installed locally, so local image builds and Docker Compose validation were not run; those checks are configured to run on the GitHub-hosted Ubuntu runner.
