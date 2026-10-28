# IPAM (core MVP)

FastAPI + MariaDB backend, dependency-free static frontend, Docker Compose deployment.

## Features
Sections, IPv4/IPv6 subnets with overlap detection (per VRF), automatic free-space and next-free
display, address management, ICMP subnet scan, VLANs, VRFs, devices, IP search, CSV import/export,
local + LDAP/AD login, e-mail password reset, split-screen login with carousel, admin/operator/viewer roles with per-section read/write grants, audit log, REST API.

Not yet built (planned phases): NAT, racks, locations, IP request workflow, PowerDNS sync, RIPE import,
e-mail notifications, custom fields, translations, IP calculator UI, RADIUS.

## Run with Docker (recommended)
Requires Docker Engine 24+ and the Compose plugin on the server.

    cp .env.example .env && chmod 600 .env     # then fill in DB_PASSWORD, IPAM_SECRET_KEY,
                                               # IPAM_PUBLIC_URL, IPAM_BOOTSTRAP_ADMIN_PASSWORD
    ./docker/make-selfsigned.sh ipam.example.com   # or copy your CA-issued fullchain.pem / privkey.pem into ./certs
    docker compose up -d --build
    docker compose ps                          # all three should be healthy/running

Open https://ipam.example.com and log in with the bootstrap admin. Afterwards delete
`IPAM_BOOTSTRAP_ADMIN_*` from `.env` and run `docker compose up -d`.

Containers: `db` (MariaDB 11.4, internal network only), `backend` (API; non-root, read-only filesystem,
all capabilities dropped), `web` (nginx with TLS, serves the UI and proxies `/api`).
Only ports 80 (redirect) and 443 are published.

Useful commands: `docker compose logs -f backend`, `docker compose down` (keeps data),
backup: `docker compose exec -T db sh -c 'mariadb-dump -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE"' | gzip > ipam-$(date +%F).sql.gz`.

Subnet scans leave the backend container through the Docker host's network, so the host must be able to
route to the VLANs you scan; replies appear to come from the host (NAT).

## Native install (alternative)
`sudo bash deploy/install.sh`, then see `deploy/nginx.conf`. Docker is the documented path.

## Develop / test
    cd backend && python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements-dev.txt
    pytest && ruff check app tests && bandit -r app

## Security design
- Argon2id password hashes; 12+ char policy; constant-time-ish login for unknown users.
- Short-lived JWT (15 min) kept in JS memory (not localStorage/cookies, so no CSRF); logout and any
  password/role change bump `token_version`, revoking tokens immediately.
- Lockout after 5 failures per username and per client IP (in-memory; single worker).
- RBAC enforced server-side on every route; per-section grants; viewers can never write.
- SQLAlchemy ORM only (no string-built SQL); Pydantic validation; `ipaddress` for all IP parsing.
- LDAP: filter escaping, empty-password rejection, certificate validation, ldaps.
- Scanner calls `ping` with an argument list (no shell) on validated IPs, size-capped.
- CSV: size/row caps; formula-injection neutralised on export.
- UI renders data via `textContent` only; strict CSP (`script-src 'self'`).
- systemd sandboxing; code owned by root; secrets in a 640 env file; API docs disabled.
- Audit log for logins and every change.

## Known limits / next hardening steps
- Lockout state is per-process; add Redis if you run multiple workers.
- No schema migrations yet (`init-db` uses create_all); add Alembic before the first upgrade.
- No MFA; put the app behind your SSO/VPN or add TOTP.
- Back up MariaDB regularly.
