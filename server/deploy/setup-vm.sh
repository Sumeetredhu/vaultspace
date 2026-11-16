#!/usr/bin/env bash
# One-time setup of a fresh Ubuntu/Debian VM for VaultSpace. Run with sudo from the folder
# that contains the copied project:   sudo bash server/deploy/setup-vm.sh <public-ip-or-hostname>
set -euo pipefail
HOST_NAME="${1:?usage: setup-vm.sh <public-ip-or-hostname>}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a   # never stop for interactive prompts

echo "== 1. System updates and automatic security updates"
apt-get update -y && apt-get upgrade -y
apt-get install -y curl xz-utils openssl ufw unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

echo "== 2. Node.js LTS from nodejs.org, checksum verified"
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 22 ]; then
  BASE=https://nodejs.org/dist/latest-v24.x
  FILE=$(curl -fsSL $BASE/SHASUMS256.txt | grep -o 'node-v[0-9.]*-linux-x64.tar.xz' | head -1)
  curl -fsSLO "$BASE/$FILE"
  curl -fsSL $BASE/SHASUMS256.txt | grep " $FILE\$" | sha256sum -c -
  tar -xJf "$FILE" -C /usr/local --strip-components=1 --exclude CHANGELOG.md --exclude LICENSE --exclude README.md
  rm "$FILE"
fi
node --version

echo "== 3. Service user, code and data folders"
id vaultspace >/dev/null 2>&1 || useradd --system --home /var/lib/vaultspace --shell /usr/sbin/nologin vaultspace
mkdir -p /opt/vaultspace /var/lib/vaultspace
rm -rf /opt/vaultspace/server && cp -r "$SRC" /opt/vaultspace/server
rm -rf /opt/vaultspace/server/data
chown -R root:root /opt/vaultspace && chmod -R go-w /opt/vaultspace
chown -R vaultspace:vaultspace /var/lib/vaultspace && chmod 700 /var/lib/vaultspace

echo "== 4. TLS key and certificate (the private key never leaves this VM)"
if [ ! -f /var/lib/vaultspace/tls/key.pem ]; then
  (cd /opt/vaultspace/server && VS_TLS_OUT=/var/lib/vaultspace/tls bash scripts/make-cert.sh "$HOST_NAME")
  chown -R vaultspace:vaultspace /var/lib/vaultspace/tls
fi
install -m 644 /var/lib/vaultspace/tls/cert.pem /opt/vaultspace/cert.pem   # public part only, for building the app

echo "== 5. Configuration"
if [ ! -f /etc/vaultspace.env ]; then
  cp /opt/vaultspace/server/deploy/vaultspace.env.example /etc/vaultspace.env
  echo ">> Edit /etc/vaultspace.env and add the email settings, then run: systemctl restart vaultspace"
fi
chown root:root /etc/vaultspace.env && chmod 600 /etc/vaultspace.env

echo "== 6. Firewall: only SSH and HTTPS"
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 443/tcp
ufw --force enable

echo "== 7. Nightly backups (03:30, last 7 days kept)"
mkdir -p /var/lib/vaultspace/backups && chown vaultspace:vaultspace /var/lib/vaultspace/backups
cp /opt/vaultspace/server/deploy/vaultspace-backup.service /opt/vaultspace/server/deploy/vaultspace-backup.timer /etc/systemd/system/

echo "== 8. Service"
cp /opt/vaultspace/server/deploy/vaultspace.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vaultspace vaultspace-backup.timer
sleep 2
systemctl --no-pager status vaultspace | head -5
echo "Done. The app certificate is at /opt/vaultspace/cert.pem."
