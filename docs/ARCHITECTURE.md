# Architecture

## Components

### Frontend (`frontend/`)
Static single-page dashboard (vanilla HTML/CSS/JS + Chart.js), served by
**nginx**, which also reverse-proxies `/api/*` and the `/api/ws` WebSocket to
the backend. No Node build step — works offline; Chart.js is vendored into the
image at build time. CSP and security headers are set in `nginx.conf`.

### Backend (`backend/app/`)
**FastAPI** application.

```
main.py            app factory, CORS, security headers, lifespan, router wiring
config.py          env-driven settings (pydantic-settings)
database.py        SQLAlchemy engine/session
models.py          User, MetricSample, Event, Alert, AuditLog
schemas.py         pydantic request/response models
core/security.py   bcrypt + JWT
deps.py            auth dependencies, require_admin RBAC
audit.py           audit-trail writer
websocket.py       live-metric broadcast hub
collectors.py      APScheduler jobs: sample metrics, ingest logs, alert, prune
routers/           auth, system, security, firewall, logs, services, alerts
services/          host integrations:
    runner.py            allow-listed, shell-free command execution (+nsenter)
    system_monitor.py    psutil metrics, per-core, processes
    firewall.py          ufw parsing & control
    fail2ban.py          jails, ban/unban
    log_collector.py     tail+parse auth/ufw/syslog into events
    security_audit.py    ports, sessions, posture score, scanners
    package_manager.py   apt updates
    service_manager.py   systemd control (managed set)
```

### Database (PostgreSQL)
Stores users, metric history (7-day retention), parsed events (30-day),
alerts, and the audit log. Never published to the host — only reachable on the
internal Docker network.

## Data flow

1. **APScheduler** in the backend samples host metrics every
   `SAMPLE_INTERVAL_SECONDS` → persists a `MetricSample` → checks thresholds →
   broadcasts to connected dashboards over WebSocket.
2. Every `SCAN_INTERVAL_SECONDS` it tails host log files, parses new lines into
   `Event` rows, and raises `Alert`s on brute-force bursts.
3. The dashboard pulls REST snapshots per tab and receives live metric pushes
   over the WebSocket.
4. Admin actions (firewall, services, bans, updates) call control endpoints →
   `runner.py` (gated + allow-listed) → host → result + `AuditLog` entry.

## Host integration

The backend sees the host through:
- **Read:** bind-mounts of `/var/log` and `/proc` (read-only) + `pid: host`.
- **Control (optional):** `nsenter -t 1` into host namespaces from a privileged
  container, **or** running natively under systemd (no nsenter needed —
  `USE_NSENTER=false`).

The `runner.py` allow-list (`ufw`, `fail2ban-client`, `systemctl`, `apt-get`,
`auditctl`, `ss`, scanners, …) is the single chokepoint for everything that
touches the host. Adding a capability = adding a binary there + a typed service
wrapper. Arbitrary strings are never executed.

## Extending

- **New metric:** add to `system_monitor.sample()` + a column on `MetricSample`.
- **New event source:** add a `(filename, parser)` pair in `log_collector.py`.
- **New host action:** add the binary to `ALLOWED_BINARIES`, write a service
  wrapper, expose a `require_admin` router with an `audit.record(...)` call.
- **New alert rule:** extend `collectors.py`.

## Security boundaries

| Boundary | Control |
|----------|---------|
| Network → dashboard | nginx, CSP, optional TLS, LAN-only UFW rule |
| Dashboard → API | JWT bearer, CORS allow-list |
| API → privileged action | `require_admin` RBAC + `ALLOW_HOST_COMMANDS` gate |
| API → host command | binary allow-list, list-args (no shell) |
| API → DB | internal network only, credentialed |
| Action accountability | append-only `audit_log` |
