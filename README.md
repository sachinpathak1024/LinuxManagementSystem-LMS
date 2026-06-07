# 🛡️ Sentinel

**A single-pane dashboard to monitor, secure, and manage your local Ubuntu laptop/desktop environment.**

Sentinel brings system monitoring, security posture, firewall control, log
aggregation, intrusion detection, service control, and patch management into one
self-hosted web app — deployed with Docker Compose.

> Built for a *local* machine you own. It is intentionally powerful: with host
> control enabled it can change firewall rules, ban IPs, restart services, and
> apply updates. Read [docs/SECURITY.md](docs/SECURITY.md) before enabling that.

---

## Features

| Area | What you get |
|------|--------------|
| 📊 **Monitoring** | Live CPU / memory / disk / load / network charts (WebSocket), top processes, 7-day history |
| 🔒 **Security posture** | 0–100 hardening score with actionable checks, listening ports, exposed-port detection, sessions & failed logins |
| 🧱 **Firewall (UFW)** | View status, enable/disable, default-deny, add/delete rules from the UI |
| 🚫 **Intrusion prevention** | fail2ban jails, banned IPs, ban/unban, SSH brute-force burst alerts |
| 📜 **Log & event pipeline** | Parses `auth.log`, `ufw.log`, `syslog` into searchable, severity-tagged events |
| 🗒️ **Raw logs** | Browse & tail host log files read-only |
| ⚙️ **Services** | Inspect & control security-relevant systemd units (ufw, fail2ban, ssh, auditd, …) |
| ⬆️ **Updates** | See upgradable/security packages, refresh index, apply security updates |
| 🧪 **Scanners** | On-demand Lynis / rkhunter / ClamAV runs |
| 📝 **Audit** | Every privileged action through Sentinel is recorded |
| 🔔 **Alerts** | Threshold breaches & security bursts raised and acknowledgeable |

## Architecture

```
┌────────────┐   /api   ┌──────────────┐         ┌────────────┐
│  Frontend  │ ───────▶ │   Backend    │ ──────▶ │ PostgreSQL │
│  nginx +   │ ◀─ ws ── │  FastAPI +   │         │  (events,  │
│  Chart.js  │          │  psutil +    │         │  metrics,  │
└────────────┘          │  collectors  │         │  audit)    │
                        └──────┬───────┘         └────────────┘
                               │ read-only mounts + (optional) nsenter
                               ▼
                     Host: /var/log, /proc, ufw, fail2ban, systemctl, apt
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detail.

## Quick start

```bash
# 1. Harden the host (UFW, fail2ban, auditd, AppArmor, SSH, sysctl, AV…)
sudo bash deploy/harden.sh

# 2. Install Docker (if needed) + generate secrets + launch
sudo bash deploy/install.sh

# 3. Open the dashboard
xdg-open http://localhost:8080
# Login with ADMIN_USERNAME / ADMIN_PASSWORD from .env
```

Manual route:

```bash
cp .env.example .env          # edit every CHANGE_ME value
docker compose up -d --build
```

## Enabling host control

Monitoring & log reading work out of the box (read-only). To let Sentinel
*change* firewall rules, ban IPs, control services and apply updates:

1. In `.env` set `ALLOW_HOST_COMMANDS=true`.
2. In `docker-compose.yml`, uncomment the `privileged` / `cap_add` / `/:/host`
   block on the `backend` service.
3. `docker compose up -d`.

This grants the backend root-equivalent control of the host. The safer
alternative is the **systemd deployment** in
[deploy/systemd/sentinel.service](deploy/systemd/sentinel.service), which runs
the backend natively on the host without a privileged container or exposed
Docker socket. Trade-offs are explained in [docs/SECURITY.md](docs/SECURITY.md).

## Project layout

```
sentinel/
├── docker-compose.yml         # 3 services: db, backend, frontend
├── .env.example               # all configuration
├── backend/                   # FastAPI app
│   └── app/
│       ├── routers/           # REST endpoints
│       ├── services/          # host integrations (ufw, fail2ban, psutil, …)
│       ├── collectors.py      # background metric/log samplers + alerting
│       └── main.py
├── frontend/                  # nginx + static dashboard (HTML/CSS/JS + Chart.js)
├── deploy/
│   ├── harden.sh              # full Ubuntu hardening script
│   ├── install.sh             # Docker install + bootstrap
│   ├── scheduled-scan.sh      # cron deep-scan job
│   └── systemd/sentinel.service
└── docs/
    ├── SECURITY.md            # threat model + local-protection playbook
    └── ARCHITECTURE.md
```

## Default credentials

The first admin is seeded from `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `.env`
on first boot. **Change the password and rotate `SECRET_KEY` before exposing
anything.** `deploy/install.sh` auto-generates strong secrets for you.

## License

Provided as-is for managing environments you own. Review before production use.
