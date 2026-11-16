#!/usr/bin/env bash
# Installs a new version of the server code (copied to ~/vaultspace/server) and restarts the
# service. The database, keys and settings are untouched. Run with sudo:
#   sudo bash ~/vaultspace/server/deploy/update.sh
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
rm -rf /opt/vaultspace/server.new
cp -r "$SRC" /opt/vaultspace/server.new
rm -rf /opt/vaultspace/server.new/data
chown -R root:root /opt/vaultspace/server.new && chmod -R go-w /opt/vaultspace/server.new
rm -rf /opt/vaultspace/server.old
mv /opt/vaultspace/server /opt/vaultspace/server.old      # kept for a quick rollback
mv /opt/vaultspace/server.new /opt/vaultspace/server
cp /opt/vaultspace/server/deploy/*.service /opt/vaultspace/server/deploy/*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl restart vaultspace
sleep 2
systemctl --no-pager status vaultspace | head -4
