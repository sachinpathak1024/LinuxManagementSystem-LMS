#!/usr/bin/env bash
# Periodic deep security scans — wire into cron / systemd timer.
#   sudo cp deploy/scheduled-scan.sh /usr/local/bin/sentinel-scan
#   sudo crontab -e   ->   30 3 * * *  /usr/local/bin/sentinel-scan
set -euo pipefail
LOG=/var/log/sentinel-scan.log
exec >>"$LOG" 2>&1
echo "===== $(date -Is) scheduled scan ====="

echo "--- rkhunter ---";  rkhunter --update -q || true; rkhunter --check --sk --nocolors || true
echo "--- AIDE integrity ---"; aide --check || true
echo "--- ClamAV (home dirs) ---"; freshclam -q || true; clamscan -r -i /home || true
echo "--- Lynis quick audit ---"; lynis audit system --quick --no-colors || true
echo "===== done ====="
