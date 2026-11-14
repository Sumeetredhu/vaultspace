#!/usr/bin/env bash
# Creates the server's TLS private key and a self-signed certificate.
# The Android app ships with this certificate and trusts ONLY it (certificate pinning), so no
# other certificate, not even one from a real certificate authority, can intercept app traffic.
#
# Usage:   scripts/make-cert.sh <server-ip-or-hostname> [more names...]
# Then copy data/tls/cert.pem to android/app/src/main/res/raw/server_cert.pem and rebuild the app.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${VS_TLS_OUT:-data/tls}"
mkdir -p "$OUT"
chmod 700 "$OUT" 2>/dev/null || true

SAN=""
for h in "$@" 10.0.2.2 127.0.0.1 localhost; do   # 10.0.2.2 = the laptop, as seen from the Android emulator
  if [[ $h =~ ^[0-9.]+$ ]]; then SAN+="IP:$h,"; else SAN+="DNS:$h,"; fi
done

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -subj "/CN=VaultSpace" -addext "subjectAltName=${SAN%,}" -addext "extendedKeyUsage=serverAuth" \
  -keyout "$OUT/key.pem" -out "$OUT/cert.pem" 2>/dev/null
chmod 600 "$OUT/key.pem"
echo "Created $OUT/cert.pem for ${SAN%,}"
