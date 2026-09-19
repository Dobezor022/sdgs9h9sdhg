#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || exec sudo -E "$0" "$@"
BUNDLE="${1:?Укажите tar.gz с серверным обновлением}"
VERSION="${2:?Укажите версию, например 2.0.0}"
CODE="${3:?Укажите version code, например 20000}"
DOMAIN="${FEDMES_PUBLIC_ORIGIN:-https://support-walrus.msk.ru}"
ROOT=/var/lib/fedmes/server-updates
FILES="$ROOT/files"
mkdir -p "$FILES"
SHA="$(sha256sum "$BUNDLE" | awk '{print $1}')"
SIZE="$(stat -c %s "$BUNDLE")"
NAME="FedMes-server-${VERSION}-${CODE}-${SHA:0:12}.tar.gz"
install -o fedmes -g fedmes -m 0644 "$BUNDLE" "$FILES/$NAME"
python3 - "$ROOT/latest.json" "$VERSION" "$CODE" "$DOMAIN/server-updates/files/$NAME" "$SHA" "$SIZE" <<'PY'
import json, os, sys, tempfile
path, version, code, url, sha, size = sys.argv[1:]
data = {
  "version": version,
  "version_code": int(code),
  "download_url": url,
  "sha256": sha,
  "size_bytes": int(size),
  "published_at": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat().replace('+00:00','Z'),
}
os.makedirs(os.path.dirname(path), exist_ok=True)
fd, tmp = tempfile.mkstemp(prefix='latest-', suffix='.json', dir=os.path.dirname(path))
with os.fdopen(fd, 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
    f.write('\n')
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
chown -R fedmes:fedmes "$ROOT"
find "$ROOT" -type d -exec chmod 0755 {} +
find "$ROOT" -type f -exec chmod 0644 {} +
echo "Опубликовано: $DOMAIN/server-updates/latest.json"
