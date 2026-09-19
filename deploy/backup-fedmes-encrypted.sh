#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

DATA_DIR="${FEDMES_DATA_DIR:-/var/lib/fedmes}"
CONFIG_DIR="${FEDMES_CONFIG_DIR:-/etc/fedmes}"
OUTPUT_DIR="${FEDMES_BACKUP_DIR:-/var/backups/fedmes}"
RECIPIENT_FILE="${FEDMES_BACKUP_RECIPIENT_FILE:-/etc/fedmes/backup-recipient.txt}"

for command in age sqlite3 tar sha256sum find sort xargs; do
  command -v "$command" >/dev/null 2>&1 || { echo "Missing required command: $command" >&2; exit 1; }
done
[[ -s "$RECIPIENT_FILE" ]] || { echo "Missing age recipient file: $RECIPIENT_FILE" >&2; exit 1; }
[[ -f "$DATA_DIR/fedmes.sqlite3" ]] || { echo "Missing FedMes database" >&2; exit 1; }

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_id="fedmes-${stamp}"
work="$(mktemp -d /var/tmp/fedmes-backup.XXXXXX)"
trap 'rm -rf "$work"' EXIT
install -d -m 0700 "$work/payload/data" "$work/payload/config" "$OUTPUT_DIR"

sqlite3 "$DATA_DIR/fedmes.sqlite3" ".timeout 30000" ".backup '$work/payload/data/fedmes.sqlite3'"
sqlite3 "$work/payload/data/fedmes.sqlite3" "PRAGMA integrity_check;" | grep -qx 'ok'
[[ -z "$(sqlite3 "$work/payload/data/fedmes.sqlite3" 'PRAGMA foreign_key_check;' | head -n1)" ]] || {
  echo "Foreign key check failed" >&2
  exit 1
}

for directory in media keys; do
  if [[ -d "$DATA_DIR/$directory" ]]; then
    cp -a -- "$DATA_DIR/$directory" "$work/payload/data/"
  fi
done
if [[ -d "$CONFIG_DIR" ]]; then
  cp -a -- "$CONFIG_DIR/." "$work/payload/config/"
fi

schema_version="$(sqlite3 "$work/payload/data/fedmes.sqlite3" 'SELECT COALESCE(MAX(version),0) FROM schema_migrations;')"
[[ "$schema_version" =~ ^[0-9]+$ ]] || { echo "Invalid schema version" >&2; exit 1; }
cat > "$work/payload/manifest.json" <<JSON
{"backup_id":"$backup_id","created_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","schema_version":$schema_version,"format_version":2,"cipher":"age","database":"data/fedmes.sqlite3"}
JSON
(
  cd "$work/payload"
  find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
)

tar --sort=name --owner=0 --group=0 --numeric-owner -C "$work/payload" -cf "$work/$backup_id.tar" .
recipient="$(tr -d '\r\n' < "$RECIPIENT_FILE")"
[[ "$recipient" == age1* || "$recipient" == age-plugin-* ]] || { echo "Invalid age recipient" >&2; exit 1; }
age -r "$recipient" -o "$OUTPUT_DIR/$backup_id.tar.age" "$work/$backup_id.tar"
sha256sum "$OUTPUT_DIR/$backup_id.tar.age" > "$OUTPUT_DIR/$backup_id.tar.age.sha256"
chmod 0600 "$OUTPUT_DIR/$backup_id.tar.age" "$OUTPUT_DIR/$backup_id.tar.age.sha256"
echo "$OUTPUT_DIR/$backup_id.tar.age"
