#!/usr/bin/env bash
# ============================================================================
# Sentinel — Ubuntu host hardening
#
# Installs and configures the full local-protection stack that the Sentinel
# dashboard then monitors and manages:
#   UFW · fail2ban · auditd · AppArmor · unattended-upgrades · SSH hardening
#   sysctl kernel hardening · ClamAV · rkhunter · Lynis · AIDE · process acct
#
# Usage:   sudo bash deploy/harden.sh
# Re-run safe (idempotent-ish). Review every section before running in prod.
# Tested on Ubuntu 20.04 / 22.04 / 24.04.
# ============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo bash $0"; exit 1; fi

# Allow overriding the SSH port you want to keep open (default 22).
SSH_PORT="${SSH_PORT:-22}"
# Comma-separated extra ports to allow inbound, e.g. "80/tcp,443/tcp"
EXTRA_ALLOW="${EXTRA_ALLOW:-}"
# Dashboard port (only if you expose it on the LAN; default keep local only)
DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"

log() { echo -e "\n\033[1;32m==>\033[0m $*"; }

log "Updating package index"
apt-get update -y

log "Installing security tooling"
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ufw fail2ban auditd audispd-plugins apparmor apparmor-utils apparmor-profiles \
  unattended-upgrades apt-listchanges \
  clamav clamav-daemon rkhunter lynis aide aide-common \
  acct sysstat needrestart libpam-pwquality

# ---------------------------------------------------------------------------
log "Configuring UFW (default deny inbound, allow outbound)"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw limit "${SSH_PORT}/tcp" comment 'SSH rate-limited'
if [[ -n "$EXTRA_ALLOW" ]]; then
  IFS=',' read -ra PORTS <<< "$EXTRA_ALLOW"
  for p in "${PORTS[@]}"; do ufw allow "$p"; done
fi
# Dashboard: allow only from localhost by default (uncomment to expose on LAN)
# ufw allow from 192.168.0.0/16 to any port "$DASHBOARD_PORT" proto tcp comment 'Sentinel LAN'
ufw logging on
ufw --force enable

# ---------------------------------------------------------------------------
log "Configuring fail2ban (sshd jail + recidive)"
cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd
banaction = ufw
destemail = root@localhost
action = %(action_)s

[sshd]
enabled = true
port    = ${SSH_PORT}
maxretry = 4

[recidive]
enabled  = true
bantime  = 1w
findtime = 1d
maxretry = 5
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# ---------------------------------------------------------------------------
log "Enabling auditd with a baseline rule set"
cat >/etc/audit/rules.d/sentinel.rules <<'EOF'
## Watch sensitive files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
## Track privilege escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privesc
## Track network config changes
-w /etc/hosts -p wa -k hosts
-w /etc/network/ -p wa -k network
## Login / logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
EOF
systemctl enable --now auditd
augenrules --load || true

# ---------------------------------------------------------------------------
log "Enabling AppArmor"
systemctl enable --now apparmor
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# ---------------------------------------------------------------------------
log "Enabling unattended security upgrades"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
sed -i 's|//\s*"\${distro_id}:\${distro_codename}-security";|        "\${distro_id}:\${distro_codename}-security";|' \
  /etc/apt/apt.conf.d/50unattended-upgrades || true
systemctl enable --now unattended-upgrades || true

# ---------------------------------------------------------------------------
log "Hardening SSH (key-only, no root login)"
SSHD=/etc/ssh/sshd_config.d/99-sentinel-hardening.conf
cat >"$SSHD" <<EOF
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
EOF
echo ">>> SSH set to key-only. Ensure you have a working SSH key before reconnecting!"
sshd -t && systemctl reload ssh || echo "sshd config test failed — NOT reloaded"

# ---------------------------------------------------------------------------
log "Applying sysctl kernel/network hardening"
cat >/etc/sysctl.d/99-sentinel.conf <<'EOF'
# IP spoofing / source routing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
# SYN flood protection
net.ipv4.tcp_syncookies = 1
# Ignore ICMP broadcast / bogus responses
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
sysctl --system >/dev/null

# ---------------------------------------------------------------------------
log "Enabling antivirus & integrity tooling"
systemctl stop clamav-freshclam || true
freshclam || true
systemctl enable --now clamav-freshclam || true
systemctl enable --now clamav-daemon || true

# Weekly rkhunter + a baseline
rkhunter --propupd -q || true

# AIDE filesystem integrity baseline (can take a while)
if [[ ! -f /var/lib/aide/aide.db ]]; then
  log "Building AIDE integrity database (may take several minutes)"
  aideinit -y -f || aideinit || true
  [[ -f /var/lib/aide/aide.db.new ]] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || true
fi

# Process accounting
systemctl enable --now acct 2>/dev/null || systemctl enable --now psacct 2>/dev/null || true

# ---------------------------------------------------------------------------
log "Setting password quality policy"
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
retry = 3
EOF

log "Done. Recommended next steps:"
cat <<'EOF'
  * Reconnect over SSH in a NEW window to confirm key-auth works before closing this session.
  * Run a baseline audit:   sudo lynis audit system
  * Review firewall:        sudo ufw status verbose
  * Review fail2ban:        sudo fail2ban-client status sshd
  * Bring up Sentinel:      cd sentinel && cp .env.example .env && docker compose up -d --build
EOF
