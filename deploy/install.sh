#!/usr/bin/env bash
# ============================================================================
# Sentinel — one-shot installer for Ubuntu
#   - installs Docker Engine + compose plugin (if missing)
#   - prepares .env
#   - builds & starts the stack
#
# Usage:   sudo bash deploy/install.sh
# ============================================================================
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo bash $0"; exit 1; fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

log() { echo -e "\n\033[1;34m==>\033[0m $*"; }

if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine"
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    >/etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
fi

if [[ ! -f .env ]]; then
  log "Creating .env from template — generating secrets"
  cp .env.example .env
  SECRET=$(openssl rand -hex 48)
  DBPASS=$(openssl rand -hex 16)
  ADMINPASS=$(openssl rand -hex 12)
  sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${SECRET}|" .env
  sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${DBPASS}|" .env
  sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${ADMINPASS}|" .env
  echo ">>> Generated admin password: ${ADMINPASS}"
  echo ">>> (saved in .env — change it after first login)"
fi

log "Building and starting Sentinel"
docker compose up -d --build

log "Sentinel is starting. Dashboard: http://localhost:${DASHBOARD_PORT:-8080}"
echo "Login with admin user from .env (ADMIN_USERNAME / ADMIN_PASSWORD)."
echo "To enable host control (ufw/systemctl/apt from the UI), see docs/SECURITY.md."
