#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || exec sudo -E bash "$0" "$@"

if [[ "${1:-}" != "--confirm-wipe" ]]; then
  echo "ОТМЕНЕНО: эта команда удаляет ВСЕ чаты, медиа, QR-приглашения, устройства и сессии."
  echo "Для подтверждения: sudo $0 --confirm-wipe"
  exit 2
fi

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP="/root/fedmes-before-wipe-${STAMP}"
mkdir -p "$BACKUP"
for path in /var/lib/fedmes /etc/fedmes; do
  if [[ -e "$path" ]]; then cp -a "$path" "$BACKUP/"; fi
done

systemctl stop fedmes-maintainer.service fedmes-update.service fedmes.service 2>/dev/null || true
rm -rf /var/lib/fedmes
install -d -o fedmes -g fedmes -m 0700 \
  /var/lib/fedmes \
  /var/lib/fedmes/media \
  /var/lib/fedmes/maintenance \
  /var/lib/fedmes/updates \
  /var/lib/fedmes/updates/files \
  /var/lib/fedmes/server-updates \
  /var/lib/fedmes/server-updates/files
if [[ -f "$DIR/releases.json" ]]; then
  install -o fedmes -g fedmes -m 0600 "$DIR/releases.json" /var/lib/fedmes/updates/releases.json
fi
systemctl start fedmes.service
systemctl start fedmes-update.service || true
systemctl start fedmes-maintainer.service

for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:8008/health/live >/dev/null 2>&1 && break
  sleep 1
done

echo "Все серверные данные FedMes удалены. Резервная копия: $BACKUP"
echo "Создайте новые QR-приглашения. После сборки клиентов заново опубликуйте APK/EXE."
