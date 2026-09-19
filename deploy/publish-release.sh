#!/usr/bin/env bash
set -Eeuo pipefail

VERSION_NAME="3.0.0"
VERSION_CODE="30000"
MINIMUM_CODE="30000"
NORMAL_APK=""
HUAWEI_APK=""
WINDOWS_EXE=""
NOTES="FedMes 3.0.0 build 30000: Rust production backend, event-driven sync, optimistic low-latency messaging, Bridge 1.9 FedUI, realtime/media hardening, Bridge 1.9 FedUI, realtime/media hardening, secure-session fixes and schema-14 compatibility."

usage() {
  cat <<'USAGE'
Использование:
  sudo fedmes-publish-release \
    --normal /path/FedMes-normal.apk \
    --huawei /path/FedMes-huawei.apk \
    --windows /path/FedMes.Desktop.exe \
    [--version 3.0.0] [--version-code 30000] [--minimum-code 30000] \
    [--notes "Описание"]
USAGE
}

while (($#)); do
  case "$1" in
    --version) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VERSION_NAME="$2"; shift 2 ;;
    --version-code) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; VERSION_CODE="$2"; shift 2 ;;
    --minimum-code) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; MINIMUM_CODE="$2"; shift 2 ;;
    --normal) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; NORMAL_APK="$2"; shift 2 ;;
    --huawei) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; HUAWEI_APK="$2"; shift 2 ;;
    --windows) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; WINDOWS_EXE="$2"; shift 2 ;;
    --notes) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; NOTES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный параметр: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { echo "Запустите через sudo." >&2; exit 1; }
[[ "$VERSION_NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][a-zA-Z0-9]+)?$ ]] || { echo "Некорректная версия." >&2; exit 1; }
[[ "$VERSION_CODE" =~ ^[0-9]+$ && "$MINIMUM_CODE" =~ ^[0-9]+$ ]] || { echo "Коды версии должны быть числами." >&2; exit 1; }
(( MINIMUM_CODE <= VERSION_CODE )) || { echo "minimum-code не может быть больше version-code." >&2; exit 1; }
for file in "$NORMAL_APK" "$HUAWEI_APK" "$WINDOWS_EXE"; do
  [[ -f "$file" ]] || { echo "Файл не найден: $file" >&2; exit 1; }
done

UPDATE_ROOT="/var/lib/fedmes/updates"
FILES_DIR="$UPDATE_ROOT/files"
MANIFEST="$UPDATE_ROOT/releases.json"
install -d -o fedmes -g fedmes -m 0700 "$UPDATE_ROOT" "$FILES_DIR"

NORMAL_SHA="$(sha256sum "$NORMAL_APK" | awk '{print $1}')"
HUAWEI_SHA="$(sha256sum "$HUAWEI_APK" | awk '{print $1}')"
WINDOWS_SHA="$(sha256sum "$WINDOWS_EXE" | awk '{print $1}')"
NORMAL_NAME="FedMes-Android-${VERSION_NAME}-${VERSION_CODE}-${NORMAL_SHA:0:12}.apk"
HUAWEI_NAME="FedMes-Huawei-${VERSION_NAME}-${VERSION_CODE}-${HUAWEI_SHA:0:12}.apk"
WINDOWS_NAME="FedMes-Windows-${VERSION_NAME}-${VERSION_CODE}-${WINDOWS_SHA:0:12}.exe"
install -o fedmes -g fedmes -m 0600 "$NORMAL_APK" "$FILES_DIR/$NORMAL_NAME"
install -o fedmes -g fedmes -m 0600 "$HUAWEI_APK" "$FILES_DIR/$HUAWEI_NAME"
install -o fedmes -g fedmes -m 0600 "$WINDOWS_EXE" "$FILES_DIR/$WINDOWS_NAME"

export VERSION_NAME VERSION_CODE MINIMUM_CODE NOTES FILES_DIR NORMAL_NAME HUAWEI_NAME WINDOWS_NAME MANIFEST
python3 - <<'PYMANIFEST'
import datetime, hashlib, json, os, pathlib, tempfile
root = pathlib.Path(os.environ["FILES_DIR"])

def artifact(name, note):
    path = root / name
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "version_name": os.environ["VERSION_NAME"],
        "version_code": int(os.environ["VERSION_CODE"]),
        "minimum_supported_code": int(os.environ["MINIMUM_CODE"]),
        "file_name": name,
        "sha256": digest.hexdigest(),
        "size_bytes": path.stat().st_size,
        "notes": note,
        "published_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
manifest = {
    "schema": 2,
    "releases": {
        "android-normal": artifact(os.environ["NORMAL_NAME"], os.environ["NOTES"]),
        "android-huawei": artifact(os.environ["HUAWEI_NAME"], os.environ["NOTES"] + " Huawei/HarmonyOS."),
        "windows-x64": artifact(os.environ["WINDOWS_NAME"], os.environ["NOTES"] + " Windows x64."),
    },
}
destination = pathlib.Path(os.environ["MANIFEST"])
fd, temporary = tempfile.mkstemp(prefix="releases-", suffix=".json", dir=str(destination.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYMANIFEST
chown fedmes:fedmes "$MANIFEST"
chmod 0600 "$MANIFEST"

systemctl restart fedmes-update.service
health_file="$(mktemp /tmp/fedmes-update-health.XXXXXX.json)"
trap 'rm -f "$health_file"' EXIT
ready=0
for _ in $(seq 1 60); do
  if systemctl is-active --quiet fedmes-update.service && \
     curl -fsS http://127.0.0.1:8010/health >"$health_file" 2>/dev/null && \
     python3 -m json.tool "$health_file" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done
if [[ $ready -ne 1 ]]; then
  systemctl status fedmes-update.service --no-pager -l >&2 || true
  journalctl -u fedmes-update.service -n 100 --no-pager >&2 || true
  exit 1
fi
python3 -m json.tool "$MANIFEST" >/dev/null

# Manifest is healthy; remove unreferenced client artifacts from older builds.
find "$FILES_DIR" -maxdepth 1 -type f \
  \( -name 'FedMes-Android-*' -o -name 'FedMes-Huawei-*' -o -name 'FedMes-Windows-*' \) \
  ! -name "$NORMAL_NAME" \
  ! -name "$HUAWEI_NAME" \
  ! -name "$WINDOWS_NAME" \
  -delete

python3 -m json.tool "$health_file"
echo "FedMes $VERSION_NAME build $VERSION_CODE опубликован. Старые клиентские файлы обновлений удалены."
