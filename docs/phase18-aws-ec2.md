# Phase 18 — AWS EC2 deployment

This runbook prepares a single-instance EC2 deployment using the existing Docker Compose application. It does not create AWS resources, set up a production account, configure TLS, or claim a live deployment.

## Architecture

The EC2 host runs Docker Engine and the repository's Compose stack:

```text
Internet (HTTP for lab/demo only; HTTPS requires TLS configuration)
  |
  v
EC2 security group -> host port 80 -> Nginx gateway
                                    |-- /api/* and /health -> FastAPI backend
                                    `-- other paths -> React frontend

Private Compose bridge network:
  FastAPI -> PostgreSQL
  Collector -> FastAPI
  Prometheus -> FastAPI /metrics
  Grafana -> Prometheus
```

The Compose services are `nginx`, `frontend`, `backend`, `collector`, `database`, `prometheus`, and `grafana`. Only Nginx publishes the public web port. PostgreSQL, backend, collector, frontend, and Prometheus have no host-published ports. Grafana is bound to `127.0.0.1` on the EC2 host and can be accessed through an SSH tunnel. Named volumes `postgres_data`, `prometheus_data`, and `grafana_data` retain data across container recreation.

The bundled collector runs in a container and sees container-scoped metrics; it does not collect all EC2 host services, logs, or hardware metrics. To monitor the EC2 host itself, run the Linux collector natively on that host and point it at the local Nginx API (`BACKEND_URL=http://127.0.0.1`) with the same collector key. Do not send that bearer token over an unencrypted public connection.

## Suggested EC2 sizing

For a small, low-volume demonstration, start with Ubuntu Server 24.04 LTS (64-bit x86), **2 vCPU and 8 GiB RAM** (for example, `t3.large`) and an **encrypted 40 GiB gp3 EBS root volume**. This is a starting point for the seven-container stack, not a production capacity guarantee. A 2-vCPU/4-GiB instance may run the stack under light use but has less room for image builds, PostgreSQL, Prometheus, and Grafana together. Watch memory, CPU credit balance on burstable instances, and disk use; increase capacity when measured load requires it. Current instance specifications vary by family/region; see [AWS general-purpose instance specifications](https://docs.aws.amazon.com/ec2/latest/instancetypes/gp.html).

There is no single reliable monthly cost without a region, hours, traffic, and storage/backup assumptions. Estimate the chosen instance, EBS, public IPv4, data transfer, and snapshots in the [AWS Pricing Calculator](https://calculator.aws/). EBS gp3 includes baseline performance, but storage and snapshot usage still incur charges; AWS's [EC2 estimate guide](https://docs.aws.amazon.com/pricing-calculator/latest/userguide/ec2-estimates.html) lists the applicable inputs. Stop or terminate a lab instance when it is not needed and review the billing console for retained storage and snapshots.

## Security group

Create a security group for the instance. Use these inbound rules:

| Port | Protocol | Source | Use |
| --- | --- | --- | --- |
| 22 | TCP | Administrator public IP `/32` only | SSH administration |
| 80 | TCP | `0.0.0.0/0` (and `::/0` only if using IPv6) | Temporary HTTP lab/demo access |
| 443 | TCP | `0.0.0.0/0` (and `::/0` only if using IPv6) | Only after TLS is configured |

Do not add inbound rules for 3000, 5432, 8000, 8001, 9090, or any collector port. AWS recommends restricting SSH to known administrator address ranges; do not use `0.0.0.0/0` for port 22. See [AWS security group guidance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-security-group.html).

The instance also needs outbound access to install OS packages, clone the repository, and pull container images. The default security group permits outbound traffic; if you restrict egress, allow the required DNS and HTTPS destinations for the selected Ubuntu package mirrors, Git remote, and image registry.

The current Compose gateway only listens on HTTP port 80 and has no TLS certificate/listener. **Do not use this HTTP-only configuration for real credentials, personal data, or sensitive operational logs.** For an internet-facing deployment, configure TLS termination at a trusted edge or configure Nginx for TLS before opening port 443. Until then, use only a temporary non-sensitive demonstration and restrict port 80 to the demonstration client IP where possible. Do not claim HTTPS is active just because port 443 is open.

Grafana's Compose binding is `127.0.0.1:3000`; it is not accessible directly from the internet. Prometheus, the backend, PostgreSQL, and collector are not exposed by security group rules or host port mappings.

## Launch and connect

1. In the EC2 console, choose an Ubuntu Server 24.04 LTS AMI, an instance size appropriate to the workload above, an encrypted gp3 root volume, and a key pair. Apply the security group rules above. Do not put application passwords or AWS access keys in instance user data.
2. Wait for EC2 instance status checks. Connect with the correct AMI username (usually `ubuntu` for Ubuntu) and keep the private key outside the repository. Example from PowerShell or a terminal with OpenSSH:

   ```sh
   ssh -i /path/to/private-key.pem ubuntu@<EC2-public-DNS-or-IP>
   ```

   Protect the private key using the permissions required by the SSH client. AWS documents connection steps for [Linux instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-linux-inst-ssh.html).
3. Install Git and Docker Engine with its Compose plugin on the instance. On Ubuntu, follow Docker's maintained [Ubuntu installation guide](https://docs.docker.com/engine/install/ubuntu/) to add its signed apt repository, then install and verify the packages:

   ```sh
   sudo apt-get update
   sudo apt-get install -y ca-certificates curl git
   sudo install -m 0755 -d /etc/apt/keyrings
   sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   sudo chmod a+r /etc/apt/keyrings/docker.asc
   sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
   Types: deb
   URIs: https://download.docker.com/linux/ubuntu
   Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
   Components: stable
   Architectures: $(dpkg --print-architecture)
   Signed-By: /etc/apt/keyrings/docker.asc
   EOF
   sudo apt-get update
   sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   sudo systemctl enable --now docker
   sudo docker compose version
   ```

   These are upstream Docker installation steps; package availability may vary with the selected Ubuntu release and CPU architecture.
4. Confirm the commit you intend to deploy has passed the Phase 17 GitHub Actions checks. Clone the repository from its Git remote (replace the placeholder with the actual repository URL):

   ```sh
   git clone <repository-URL>
   cd <repository-directory>
   ```

   For a private repository, use an appropriately scoped read-only deploy key or another approved Git credential method. Do not put private keys in the repository.

## Configure and start Compose

1. Create a private environment file from the template and edit it on the instance:

   ```sh
   umask 077
   cp .env.example .env
   chmod 600 .env
   nano .env
   ```

2. Replace the template values with independently generated credentials of at least 32 characters for `POSTGRES_PASSWORD`, `COLLECTOR_API_KEY`, `ADMIN_API_KEY`, and `GRAFANA_ADMIN_PASSWORD`. The backend safely encodes database passwords when constructing its SQLAlchemy URL. Set `ENVIRONMENT=production`, `HTTP_PORT=80`, and `GRAFANA_PORT=3000` for the documented setup. Do not print or paste secrets into a shell command, workflow, ticket, or Git commit. `.env` is ignored by Git.
3. Check Compose configuration and build/start the stack:

   ```sh
   sudo docker compose config --quiet
   sudo docker compose up -d --build --wait
   sudo docker compose ps
   ```

   The backend waits for PostgreSQL, runs the existing Alembic migrations during startup, and then becomes ready. The other dependencies use the existing health checks and startup ordering.

### Persistent data and backups

The named Compose volumes keep PostgreSQL, Prometheus, and Grafana state across container replacement. They are stored in Docker's data directory on the EC2 EBS-backed filesystem. `docker compose down` without `-v` retains the volumes; **never use `docker compose down -v` for routine updates or shutdown.** Named volumes are not an independent backup and do not protect against instance/storage loss.

Before upgrades, make a database dump outside the checkout and protect it because it contains application data:

```sh
sudo install -d -m 700 /var/backups/opstrace
sudo docker compose exec -T database sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  | sudo tee "/var/backups/opstrace/postgres-$(date +%F-%H%M%S).sql" >/dev/null
sudo chmod 600 /var/backups/opstrace/postgres-*.sql
```

Copy backups off the instance using an approved encrypted storage process. Consider scheduled, encrypted EBS snapshots or AWS Backup for recovery from instance/storage loss; AWS does not create EBS snapshots automatically. See [EBS snapshot and backup guidance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/storage_ebs.html). Test restores periodically.

## Verify the deployment

Run these commands from the repository directory on EC2:

```sh
# Container state and health status
sudo docker compose ps

# Gateway config and proxied readiness endpoint
sudo docker compose exec nginx nginx -t
curl -fsS http://127.0.0.1/health

# FastAPI readiness directly through the gateway
curl -fsS http://127.0.0.1/api/v1/health

# Frontend response
curl -fsSI http://127.0.0.1/

# PostgreSQL readiness using the container's configured user/database
sudo docker compose exec -T database sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"'

# Prometheus active targets, queried from inside its container
sudo docker compose exec -T prometheus \
  wget -qO- 'http://127.0.0.1:9090/api/v1/targets?state=active'

# Grafana health (host binding is loopback-only)
curl -fsS http://127.0.0.1:3000/api/health

# Recent service logs
sudo docker compose logs --tail=100 nginx backend database prometheus grafana collector
```

The Prometheus target response should list `backend:8000` as `up`. Check the JSON from `/api/v1/health` and confirm `database.connected` is `true`; the endpoint may return HTTP 200 even when the database is degraded. Verify the Nginx, frontend, and database checks too. Grafana is not public: from the administrator workstation, create an SSH tunnel and then open `http://127.0.0.1:3000/` locally:

```sh
ssh -i /path/to/private-key.pem -L 3000:127.0.0.1:3000 ubuntu@<EC2-public-DNS-or-IP>
```

The default Grafana host port is 3000. If `GRAFANA_PORT` was changed, adjust the tunnel's remote port. Use the configured Grafana credentials from the private `.env` file.

## Stop, restart, update, and rollback

- Stop services without deleting data: `sudo docker compose stop`.
- Start stopped services: `sudo docker compose start`.
- Restart a service after inspecting it: `sudo docker compose restart <service>`.
- Update from the deployed branch after checking the database backup and ensuring the checkout has no local code edits:

  ```sh
  git pull --ff-only
  sudo docker compose config --quiet
  sudo docker compose up -d --build --wait
  sudo docker compose ps
  ```

  `--ff-only` avoids creating a merge commit on the server. The backend startup automatically applies pending migrations. Review migration changes and take a database backup before updating.
- For a code rollback, record the deployed commit before updating. Check out the previous known-good commit and rebuild with `sudo docker compose up -d --build --wait`. This does not reverse database migrations. Restore a compatible database backup if a migration is not backward-compatible. Do not delete named volumes as a rollback strategy.
- To shut down containers while retaining volumes: `sudo docker compose down` (without `-v`).

## Security and operational limits

- No AWS access key is required on the EC2 host for this runbook. Use the instance's normal SSH key only for administration; do not commit it. No AWS credentials, application credentials, or production secrets are stored in this repository.
- `.env`, `.pem`, `.key`, AWS credential folders/files, and common SSH private key filenames are ignored by Git. Confirm with `git status --short` before committing deployment changes.
- Restrict SSH to a known administrator IP. Avoid exposing Grafana, Prometheus, PostgreSQL, backend, or collector ports.
- The current Nginx setup is HTTP-only. TLS, certificate renewal, automated backups, centralized log retention, monitoring/alerting of the EC2 host, and high availability are not implemented by this phase.
- Prometheus, Grafana, PostgreSQL, and container images share one host and EBS volume; resource exhaustion or host failure affects the full stack. Monitor disk consumption and plan backups/retention.
- EC2 compute, EBS, public IPv4, snapshots, and internet egress can all incur charges. Use the AWS calculator for the chosen region and expected run time; no monthly price is asserted here.

## What was tested

Validation performed for this phase: backend and collector suites (448 passed), frontend tests (4 passed), frontend TypeScript check and production build, CI configuration validator, and static YAML parsing of the Compose and GitHub Actions files. The Compose port/volume/service layout, Dockerfiles, Nginx routing, health routes, and environment template were also inspected. This environment has no Docker CLI, AWS CLI, `.env`, or configured AWS deployment context. Therefore no image build, live Compose startup, instance connection, AWS resource creation, or EC2 verification was performed for Phase 18.
