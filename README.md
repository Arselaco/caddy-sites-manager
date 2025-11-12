# Edge Stack (Caddy + Site Manager)

This project delivers a lightweight, self-healing HTTPS reverse proxy that can run the same way on Ubuntu or CentOS. It uses Caddy for automatic TLS (Lets Encrypt with ZeroSSL fallback) and a small Python sidecar that watches a domain inventory file and keeps Caddys virtual hosts in sync without downtime. No external database is required.

## Features
- Automatic HTTP/HTTPS for every domain in `domains.yaml`, including free certificates and renewals.
- Watchdog that regenerates per-site Caddy snippets when the inventory changes and triggers a zero-downtime reload.
- Works with simple strings or structured upstream definitions (host/port/scheme) and optional health checks/timeouts.
- Environment-driven configuration so you can version-control settings safely.
- Stateless: all runtime data lives in local volumes (`data/caddy`) or regular config files.

## Prerequisites
- Docker Engine 24+ and Docker Compose plugin 2.20+.
- Ability to expose ports 80/443 (and optionally 8081, etc.) on the host.
- DNS for each domain pointing at this servers public IP.

## Quick Start
1. **Copy and edit environment file**
   ```bash
   cp .env .env.local  # optional
   ```
   Update the email used for ACME (`ACME_EMAIL`) and adjust exposed ports if needed.

2. **Describe your upstreams** in `domains.yaml`:
   ```yaml
   sites:
     - domain: example.com
       aliases:
         - www.example.com
       upstream:
         host: app
         port: 8080
         scheme: http
   ```
   You can also inline a URL: `upstream: http://app:8080`.

3. **Start the stack**
   ```bash
   docker compose up -d --build
   ```

4. **Watch logs** (optional)
   ```bash
   docker compose logs -f site-manager caddy
   ```

## Domain Inventory Format (`domains.yaml`)
Each item under `sites` accepts:

- `domain` (required): primary host name.
- `aliases` (optional): extra hostnames sharing the same upstream.
- `upstream`: either a URL string or a map with `host`, `port`, `scheme` (default `http`).
- `preserve_host` (default `true`): keep original `Host` header when proxying.
- `timeouts` (optional): `dial`, `read`, `write` values understood by Caddy.
- `healthcheck` (optional): `path`/`uri`, `interval`, `timeout` for active upstream health checks.

Environment variables like `${SERVICE_URL}` can appear in strings and are expanded by the watcher.

## Runtime Layout
- `docker-compose.yml`: defines the `caddy` reverse proxy and the `site-manager` watcher.
- `config/Caddyfile`: global Caddy settings; imports generated snippets from `config/sites/`.
- `config/sites/`: auto-generated per-domain `.caddy` files (do not edit manually).
- `data/caddy/`: persisted certificates and state.
- `site-manager/`: Python watcher (Docker image) that reads `domains.yaml` and reloads Caddy through its admin API on `http://caddy:2019`.

## Maintenance
- **Adding domains**: edit `domains.yaml`. Changes are detected and applied automatically after a short debounce.
- **Removing domains**: delete the entry; the watcher removes the snippet and reloads Caddy.
- **Upgrading dependencies**: adjust `site-manager/requirements.txt` and rebuild with `docker compose build`.
- **Backups**: keep copies of `.env`, `domains.yaml`, and `data/caddy` (certs) if needed.

## Troubleshooting
- Check `docker compose ps` to ensure both services are healthy.
- Use `docker compose logs -f caddy` for certificate or proxy issues.
- If certificates fail (rate limits, resolver problems), Caddy automatically falls back to using ZeroSSL. Ensure outbound HTTPS is allowed.

## Shutdown
```bash
docker compose down
```
This preserves certificates and generated configs for the next start.
