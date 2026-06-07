# Security model & local-protection playbook

This document covers (1) how to run Sentinel safely, and (2) a complete set of
**suggestions to protect your local Ubuntu environment** — the "all set of
possible security" the tool is built around.

---

## 1. Running Sentinel safely

### What Sentinel can do
Sentinel has two capability tiers:

| Tier | Needs | Risk |
|------|-------|------|
| **Observe** (default) | read-only mounts of `/var/log`, `/proc` | low — cannot change the host |
| **Control** (opt-in) | `ALLOW_HOST_COMMANDS=true` + privileged container *or* host systemd | high — root-equivalent on the host |

### Deployment options, safest first

1. **Observe-only container (default).** Great for monitoring/forensics.
   No firewall/service/update *actions*, but everything is visible.

2. **Host systemd service** ([deploy/systemd/sentinel.service](../deploy/systemd/sentinel.service)).
   Full native control of ufw/systemctl/apt **without** a privileged container
   or an exposed Docker socket. Bind it to `127.0.0.1` and reach the UI via the
   dashboard reverse proxy or an SSH tunnel. **Recommended for full control.**

3. **Privileged container.** Convenient (everything in compose) but the backend
   container effectively has root on the host. Only on a machine you fully own,
   never exposed to an untrusted network.

### Hardening rules baked in
- **No shell execution.** Every host command runs through an **allow-list of
  binaries** (`app/services/runner.py`) with arguments passed as a list — no
  shell, no string interpolation, so there is no command-injection surface.
- **Control is gated.** With `ALLOW_HOST_COMMANDS=false`, every state-changing
  call returns a "disabled" result instead of running.
- **RBAC.** `admin` can act; `viewer` can only read. All mutating endpoints
  require the admin role.
- **Full audit trail.** Every privileged action is written to the `audit_log`
  table and shown in the Audit tab.
- **JWT auth**, bcrypt password hashing, security headers on both nginx and the
  API, DB never published to the host network.

### Checklist before you expose anything
- [ ] Rotate `SECRET_KEY` (`openssl rand -hex 48`) and all passwords in `.env`.
- [ ] Change the seeded admin password after first login.
- [ ] Keep the dashboard bound to `localhost` or your LAN only (UFW rule).
- [ ] Put TLS in front (Caddy/Traefik/nginx + Let's Encrypt) if reaching it over a network.
- [ ] Prefer the systemd deployment over a privileged container for control.
- [ ] Never commit your real `.env`.

---

## 2. Local environment protection playbook

`deploy/harden.sh` automates most of this. Here is the full reasoning so you
can adapt it.

### 2.1 Firewall — UFW
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw limit 22/tcp          # rate-limit SSH (slows brute force)
sudo ufw logging on
sudo ufw enable
```
Principle: **default-deny inbound**, open only what you actually serve. Sentinel
flags every port bound to `0.0.0.0` so you can spot accidental exposure.

### 2.2 Intrusion prevention — fail2ban
Bans IPs after repeated auth failures; `recidive` jail bans repeat offenders for
a week. Uses the `ufw` banaction so bans show up in your firewall. Watch jails
and unban from the Security tab.

### 2.3 Audit & accountability — auditd
Baseline rules watch `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
`sshd_config`, privilege escalation (`execve` as root), and login records.
Query with `ausearch -k privesc`. Process accounting (`acct`) records every
executed command (`lastcomm`).

### 2.4 Mandatory access control — AppArmor
Confines programs to least-privilege profiles. Keep it enforcing; add profiles
for risky apps. `aa-status` is surfaced in the posture score.

### 2.5 Patch management — unattended-upgrades
Auto-applies security updates daily. Sentinel additionally shows pending
security packages and can apply them on demand. **Unpatched software is the #1
local risk** — automate it.

### 2.6 SSH hardening
- Key-only auth (`PasswordAuthentication no`), `PermitRootLogin no`.
- `MaxAuthTries 3`, short `LoginGraceTime`, idle timeout.
- Consider a non-standard port + `AllowUsers <you>`.
- ⚠️ Confirm your key works in a second session before closing your shell.

### 2.7 Kernel & network hardening — sysctl
ASLR (`randomize_va_space=2`), `kptr_restrict`, `dmesg_restrict`, reverse-path
filtering, SYN cookies, ignore ICMP redirects/broadcasts, protected hard/sym
links, no SUID core dumps. (See `deploy/harden.sh` for the full set.)

### 2.8 Antivirus & rootkit/integrity scanning
- **ClamAV** — on-access/scheduled malware scanning.
- **rkhunter / chkrootkit** — rootkit detection.
- **AIDE** — filesystem integrity baseline; alerts on tampering of system files.
- **Lynis** — periodic security audit with a hardening index.

Run them nightly via [deploy/scheduled-scan.sh](../deploy/scheduled-scan.sh), or
on demand from the Security tab.

### 2.9 Account & authentication policy
- `pwquality`: min length 12, complexity required.
- Disable unused accounts; enforce `sudo` (no direct root login).
- Consider 2FA for SSH (`libpam-google-authenticator`).

### 2.10 Logging & monitoring (the dashboard)
- Centralize: `journald` + the parsed event pipeline in Sentinel.
- Alert on: high resource use, disk filling, SSH brute-force bursts, OOM, disk
  errors, firewall blocks. All wired into `collectors.py`.
- Forward to an off-box collector (rsyslog/Loki) for tamper-resistance on
  important machines.

### 2.11 Encryption & physical security (do once, manually)
- **Full-disk encryption** (LUKS) at install time — protects data if the laptop
  is lost/stolen. Cannot be retrofitted easily; plan it.
- Encrypted swap, BIOS/UEFI password, Secure Boot, screen-lock timeout.
- Encrypted backups (restic/borg) on a 3-2-1 schedule.

### 2.12 Attack-surface reduction
- Remove unused packages/services (`systemd-analyze`, `ss -tulnp`).
- Disable services you don't use (CUPS, avahi, bluetooth) if not needed.
- Use `needrestart` to catch services running on old libraries after updates.

### Suggested cadence
| Frequency | Action |
|-----------|--------|
| Continuous | Sentinel monitoring + alerts, fail2ban, auditd |
| Daily | unattended-upgrades, log review |
| Nightly (cron) | rkhunter, AIDE check, ClamAV, Lynis quick audit |
| Weekly | review audit log, exposed ports, firewall rules |
| Monthly | full Lynis audit, rotate credentials, test backup restore |

---

### Threat-model summary
Sentinel defends a single-owner workstation against: remote brute-force and
network probing (UFW + fail2ban), unpatched-software exploitation
(unattended-upgrades), malware/rootkits (ClamAV/rkhunter/AIDE), privilege abuse
and config tampering (auditd + AppArmor + audit log), and resource
exhaustion/operational failure (monitoring + alerts). It does **not** replace
disk encryption, physical security, or a backup strategy — do those too.
