#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ ${EUID} -eq 0 ]] || exec sudo -E bash "$0" "$@"
[[ $# -eq 2 ]] || { echo "Usage: $0 BACKUP.tar.age AGE_IDENTITY" >&2; exit 2; }
backup="$1"
identity="$2"
DATA_DIR="${FEDMES_DATA_DIR:-/var/lib/fedmes}"
CONFIG_DIR="${FEDMES_CONFIG_DIR:-/etc/fedmes}"
for command in age tar sha256sum sqlite3 systemctl python3 curl; do command -v "$command" >/dev/null || { echo "Missing $command" >&2; exit 1; }; done
[[ -f "$backup" && -f "$identity" ]] || { echo "Backup or identity not found" >&2; exit 1; }
if [[ -f "$backup.sha256" ]]; then (cd "$(dirname "$backup")" && sha256sum -c "$(basename "$backup").sha256"); fi
work="$(mktemp -d /var/tmp/fedmes-restore.XXXXXX)"
trap 'rm -rf "$work"' EXIT
age -d -i "$identity" -o "$work/backup.tar" "$backup"
python3 - "$work/backup.tar" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1], 'r:') as archive:
    for member in archive.getmembers():
        name = member.name
        if name.startswith('/') or any(part == '..' for part in name.split('/')):
            raise SystemExit(f'unsafe archive path: {name}')
        if member.issym() or member.islnk() or member.isdev():
            raise SystemExit(f'unsupported archive entry: {name}')
PY
install -d -m 0700 "$work/payload"
tar --no-same-owner --no-same-permissions -xf "$work/backup.tar" -C "$work/payload"
(cd "$work/payload" && sha256sum -c SHA256SUMS)
sqlite3 "$work/payload/data/fedmes.sqlite3" 'PRAGMA integrity_check;' | grep -qx ok
[[ -z "$(sqlite3 "$work/payload/data/fedmes.sqlite3" 'PRAGMA foreign_key_check;' | head -n1)" ]] || exit 1
[[ -f "$work/payload/manifest.json" && -f "$work/payload/data/fedmes.sqlite3" ]] || exit 1

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
rollback_root="/root/fedmes-before-restore-${stamp}"
new_data="${DATA_DIR}.restore-new-${stamp}"
new_config="${CONFIG_DIR}.restore-new-${stamp}"
old_data="${DATA_DIR}.before-restore-${stamp}"
old_config="${CONFIG_DIR}.before-restore-${stamp}"
install -d -m 0700 "$rollback_root"
rm -rf -- "$new_data" "$new_config"
install -d -m 0700 "$new_data"
install -d -m 0750 "$new_config"
cp -a -- "$work/payload/data/." "$new_data/"
cp -a -- "$work/payload/config/." "$new_config/"
chown -R fedmes:fedmes "$new_data"
find "$new_data" -type d -exec chmod 0700 {} +
find "$new_data" -type f -exec chmod 0600 {} +
chown -R root:fedmes "$new_config"
find "$new_config" -type d -exec chmod 0750 {} +
find "$new_config" -type f -exec chmod 0640 {} +

systemctl stop fedmes.service fedmes-update.service fedmes-maintainer.service 2>/dev/null || true
data_moved=0
config_moved=0
new_data_installed=0
new_config_installed=0
restore_old() {
  systemctl stop fedmes.service fedmes-update.service fedmes-maintainer.service 2>/dev/null || true
  if [[ $new_data_installed -eq 1 ]]; then rm -rf -- "$DATA_DIR"; fi
  if [[ $new_config_installed -eq 1 ]]; then rm -rf -- "$CONFIG_DIR"; fi
  if [[ $data_moved -eq 1 && -d "$old_data" ]]; then mv -- "$old_data" "$DATA_DIR"; fi
  if [[ $config_moved -eq 1 && -d "$old_config" ]]; then mv -- "$old_config" "$CONFIG_DIR"; fi
  systemctl start fedmes.service fedmes-update.service fedmes-maintainer.service 2>/dev/null || true
}
trap 'status=$?; if [[ $status -ne 0 ]]; then restore_old; fi; rm -rf "$work" "$new_data" "$new_config"; exit $status' EXIT
if [[ -e "$DATA_DIR" ]]; then mv -- "$DATA_DIR" "$old_data"; data_moved=1; fi
if [[ -e "$CONFIG_DIR" ]]; then mv -- "$CONFIG_DIR" "$old_config"; config_moved=1; fi
mv -- "$new_data" "$DATA_DIR"
new_data_installed=1
mv -- "$new_config" "$CONFIG_DIR"
new_config_installed=1
systemctl start fedmes.service fedmes-update.service fedmes-maintainer.service
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:8008/health/live >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:8008/health/live >/dev/null
systemctl --no-pager --full status fedmes.service
printf '%s\n' "$old_data" "$old_config" > "$rollback_root/ROLLBACK-PATHS.txt"
trap - EXIT
rm -rf "$work"
echo "Restore completed. Previous data remains at $old_data and $old_config until manual verification."
