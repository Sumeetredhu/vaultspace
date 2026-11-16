#!/usr/bin/env bash
# Nightly backup: a consistent copy of the database (SQLite "VACUUM INTO"), the server secret, and
# a hard-linked snapshot of the encrypted chunks (chunks are never modified in place, so hard links
# are safe and take no extra space). Keeps the last 7 days. Everything in it is still encrypted.
set -euo pipefail
DATA="${VS_DATA:-/var/lib/vaultspace}"
OUT="$DATA/backups/$(date +%F)"
mkdir -p "$OUT"
rm -f "$OUT/vaultspace.db"
/usr/local/bin/node --no-warnings -e \
  "new (require('node:sqlite').DatabaseSync)(process.argv[1]).exec(\"VACUUM INTO '\" + process.argv[2] + \"'\")" \
  "$DATA/vaultspace.db" "$OUT/vaultspace.db"
cp "$DATA/server.secret" "$OUT/"
rm -rf "$OUT/blobs" && cp -al "$DATA/blobs" "$OUT/blobs"
ls -1d "$DATA"/backups/*/ | head -n -7 | xargs -r rm -rf
echo "backup written to $OUT"
