#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $# -eq 2 ]] || { echo "Usage: $0 BACKUP.tar.age AGE_IDENTITY" >&2; exit 2; }
backup="$1"
identity="$2"
for command in age tar sha256sum sqlite3 python3; do command -v "$command" >/dev/null || { echo "Missing $command" >&2; exit 1; }; done
[[ -f "$backup" && -f "$identity" ]] || { echo "Backup or identity not found" >&2; exit 1; }
if [[ -f "$backup.sha256" ]]; then (cd "$(dirname "$backup")" && sha256sum -c "$(basename "$backup").sha256"); fi
work="$(mktemp -d /var/tmp/fedmes-verify.XXXXXX)"
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
python3 - "$work/payload/manifest.json" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as stream:
    data = json.load(stream)
required = {'backup_id','created_at','schema_version','format_version','cipher','database'}
if not required.issubset(data) or data['format_version'] not in (1,2) or data['cipher'] != 'age':
    raise SystemExit('invalid backup manifest')
print(json.dumps(data, ensure_ascii=False, indent=2))
PY
