#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || exec sudo -E bash "$0" "$@"

BUNDLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DOMAIN="${FEDMES_DOMAIN:-support-walrus.msk.ru}"
WIPE_DATA=0
for arg in "$@"; do
  case "$arg" in
    --wipe-data) WIPE_DATA=1 ;;
    --preserve-data) WIPE_DATA=0 ;;
    *) echo "Неизвестный параметр: $arg" >&2; exit 2 ;;
  esac
done

required=(fedmes-qr fedmes-update-server fedmes-maintainer fedmes-apply-update publish-release.sh publish-required-update.sh publish-server-update.sh build-server-on-ubuntu.sh server-source.tar.gz releases.json backup-fedmes-encrypted.sh verify-fedmes-backup.sh restore-fedmes-encrypted.sh)
for file in "${required[@]}"; do [[ -f "$BUNDLE_DIR/$file" ]] || { echo "В комплекте отсутствует $file" >&2; exit 1; }; done

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/root/fedmes-before-clean-1.0.6-$STAMP"
mkdir -p "$BACKUP"
backup_path() {
  local source="$1"
  [[ -e "$source" ]] || return 0
  local destination="$BACKUP$source"
  mkdir -p "$(dirname -- "$destination")"
  cp -a "$source" "$destination"
}
for path in /opt/fedmes /etc/fedmes /etc/systemd/system/fedmes.service /etc/systemd/system/fedmes-update.service /etc/systemd/system/fedmes-maintainer.service /etc/nginx/sites-available/fedmes /var/www/fedmes; do backup_path "$path"; done
if [[ -d /var/lib/fedmes ]]; then backup_path /var/lib/fedmes; fi

CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
[[ -s "$CERT" && -s "$KEY" ]] || { echo "Не найден действующий сертификат Let's Encrypt для $DOMAIN. Защищённая установка остановлена." >&2; exit 1; }

echo "[1/10] Удаление старых программ, служб и конфигурации FedMes"
systemctl stop fedmes-maintainer.service fedmes-update.service fedmes.service 2>/dev/null || true
systemctl disable fedmes-maintainer.service fedmes-update.service fedmes.service 2>/dev/null || true
rm -rf /opt/fedmes /etc/fedmes /var/www/fedmes
rm -f /etc/systemd/system/fedmes.service /etc/systemd/system/fedmes-update.service /etc/systemd/system/fedmes-maintainer.service
rm -f /usr/local/sbin/fedmes-publish-release /usr/local/sbin/fedmes-publish-required-update /usr/local/sbin/fedmes-publish-server-update
rm -f /usr/local/sbin/fedmes-backup-encrypted /usr/local/sbin/fedmes-verify-backup /usr/local/sbin/fedmes-restore-encrypted
rm -f /etc/nginx/sites-enabled/fedmes* /etc/nginx/sites-available/fedmes*
if [[ $WIPE_DATA -eq 1 ]]; then
  rm -rf /var/lib/fedmes
else
  # Сохраняем уже опубликованные APK/EXE и releases.json. Иначе между
  # обновлением сервера и повторной публикацией клиент получил бы HTTP 503.
  rm -rf /var/lib/fedmes/maintenance
fi
systemctl daemon-reload

echo "[2/10] Установка зависимостей"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl tar gzip nginx acl python3 sqlite3 openssl age
nginx -V 2>&1 | grep -q -- '--with-http_auth_request_module' || { echo "Nginx собран без auth_request." >&2; exit 1; }
if ! id fedmes >/dev/null 2>&1; then useradd --system --user-group --home-dir /var/lib/fedmes --shell /usr/sbin/nologin fedmes; fi

echo "[3/10] Создание приватной структуры"
install -d -o root -g root -m 0755 /opt/fedmes/bin /var/www/fedmes
install -d -o root -g fedmes -m 0750 /etc/fedmes
if [[ $WIPE_DATA -eq 0 && -d "$BACKUP/etc/fedmes" ]]; then
  cp -a -- "$BACKUP/etc/fedmes/." /etc/fedmes/
  chown -R root:fedmes /etc/fedmes
  find /etc/fedmes -type d -exec chmod 0750 {} +
  find /etc/fedmes -type f -exec chmod 0640 {} +
fi
install -d -o fedmes -g fedmes -m 0700 /var/lib/fedmes /var/lib/fedmes/media /var/lib/fedmes/maintenance
install -d -o fedmes -g fedmes -m 0700 /var/lib/fedmes/updates /var/lib/fedmes/updates/files
install -d -o fedmes -g fedmes -m 0755 /var/lib/fedmes/server-updates /var/lib/fedmes/server-updates/files

if [[ ! -s /etc/fedmes/update-ticket.key ]]; then
  umask 0077
  openssl rand -hex 32 > /etc/fedmes/update-ticket.key
fi
chown root:fedmes /etc/fedmes/update-ticket.key
chmod 0640 /etc/fedmes/update-ticket.key

echo "[4/10] Сборка сервера 1.0.6"
"$BUNDLE_DIR/build-server-on-ubuntu.sh" "$BUNDLE_DIR/server-source.tar.gz" "$BUNDLE_DIR/fedmes-server"

echo "[5/10] Установка программ"
for binary in fedmes-server fedmes-qr fedmes-update-server fedmes-maintainer fedmes-apply-update; do install -o root -g root -m 0755 "$BUNDLE_DIR/$binary" "/opt/fedmes/bin/$binary"; done
install -o root -g root -m 0755 "$BUNDLE_DIR/publish-release.sh" /usr/local/sbin/fedmes-publish-release
install -o root -g root -m 0755 "$BUNDLE_DIR/publish-required-update.sh" /usr/local/sbin/fedmes-publish-required-update
install -o root -g root -m 0755 "$BUNDLE_DIR/publish-server-update.sh" /usr/local/sbin/fedmes-publish-server-update
install -o root -g root -m 0755 "$BUNDLE_DIR/backup-fedmes-encrypted.sh" /usr/local/sbin/fedmes-backup-encrypted
install -o root -g root -m 0755 "$BUNDLE_DIR/verify-fedmes-backup.sh" /usr/local/sbin/fedmes-verify-backup
install -o root -g root -m 0755 "$BUNDLE_DIR/restore-fedmes-encrypted.sh" /usr/local/sbin/fedmes-restore-encrypted
if [[ $WIPE_DATA -eq 1 || ! -s /var/lib/fedmes/updates/releases.json ]]; then
  install -o fedmes -g fedmes -m 0600 "$BUNDLE_DIR/releases.json" /var/lib/fedmes/updates/releases.json
else
  echo "Сохранён существующий releases.json и опубликованные клиентские файлы."
fi

cat > /etc/fedmes/fedmes.env <<'ENV'
FEDMES_ADDR=127.0.0.1:8008
FEDMES_DATA_DIR=/var/lib/fedmes
FEDMES_SHUTDOWN_TIMEOUT=20s
ENV
chown root:fedmes /etc/fedmes/fedmes.env
chmod 0640 /etc/fedmes/fedmes.env

echo "[6/10] Создание systemd-служб"
cat > /etc/systemd/system/fedmes.service <<'UNIT'
[Unit]
Description=FedMes family messenger server 1.0.6
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=fedmes
Group=fedmes
EnvironmentFile=/etc/fedmes/fedmes.env
ExecStart=/opt/fedmes/bin/fedmes-server serve
Restart=always
RestartSec=3s
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/fedmes
[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/fedmes-update.service <<'UNIT'
[Unit]
Description=FedMes authenticated client update service 1.0.6
After=network-online.target fedmes.service
Wants=network-online.target
[Service]
Type=simple
User=fedmes
Group=fedmes
ExecStart=/opt/fedmes/bin/fedmes-update-server --addr 127.0.0.1:8010 --manifest /var/lib/fedmes/updates/releases.json --files-dir /var/lib/fedmes/updates/files --ticket-key /etc/fedmes/update-ticket.key
Restart=always
RestartSec=3s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
ReadOnlyPaths=/var/lib/fedmes/updates /etc/fedmes/update-ticket.key
[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/fedmes-maintainer.service <<'UNIT'
[Unit]
Description=FedMes automatic repair and server updater 1.0.6
After=network-online.target nginx.service fedmes.service fedmes-update.service
Wants=network-online.target
[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/fedmes/bin/fedmes-maintainer --interval 1m --update-interval 30m --auto-server-update=true
Restart=always
RestartSec=10s
UMask=0077
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/fedmes /opt/fedmes/bin /run/systemd /etc/nginx
[Install]
WantedBy=multi-user.target
UNIT

cat > /var/www/fedmes/index.html <<'HTML'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title></title><style>*{box-sizing:border-box}html,body{width:100%;height:100%;margin:0}body{display:grid;place-items:center;background:#f4f6f8}.loader{width:42px;height:42px;border:4px solid #d9dee5;border-top-color:#6b7280;border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}</style></head><body><div class="loader" aria-hidden="true"></div></body></html>
HTML
chmod 0644 /var/www/fedmes/index.html

echo "[7/10] Настройка Nginx: TLS 1.3 и закрытый POST download"
cat > /etc/nginx/sites-available/fedmes <<NGINX
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    ssl_certificate $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols TLSv1.3;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    client_max_body_size 0;
    client_body_timeout 3600s;

    location = / {
        root /var/www/fedmes;
        try_files /index.html =404;
    }

    location = /_fedmes_update_auth {
        internal;
        proxy_pass http://127.0.0.1:8008/api/v1/auth/validate;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Authorization \$http_authorization;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }

    location = /api/v1/updates/check {
        auth_request /_fedmes_update_auth;
        auth_request_set \$fedmes_user \$upstream_http_x_fedmes_user;
        auth_request_set \$fedmes_device \$upstream_http_x_fedmes_device;
        proxy_pass http://127.0.0.1:8010;
        proxy_http_version 1.1;
        proxy_set_header Authorization \$http_authorization;
        proxy_set_header X-FedMes-Authenticated-User \$fedmes_user;
        proxy_set_header X-FedMes-Authenticated-Device \$fedmes_device;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        add_header Cache-Control "private, no-store, max-age=0" always;
    }

    location = /api/v1/updates/download {
        limit_except POST { deny all; }
        auth_request /_fedmes_update_auth;
        auth_request_set \$fedmes_user \$upstream_http_x_fedmes_user;
        auth_request_set \$fedmes_device \$upstream_http_x_fedmes_device;
        proxy_pass http://127.0.0.1:8010;
        proxy_http_version 1.1;
        proxy_set_header Authorization \$http_authorization;
        proxy_set_header X-FedMes-Authenticated-User \$fedmes_user;
        proxy_set_header X-FedMes-Authenticated-Device \$fedmes_device;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        add_header Cache-Control "private, no-store, max-age=0" always;
    }

    location ^~ /updates/files/ { return 404; }

    location = /server-updates/latest.json {
        alias /var/lib/fedmes/server-updates/latest.json;
        default_type application/json;
        add_header Cache-Control "no-store" always;
    }
    location /server-updates/files/ {
        alias /var/lib/fedmes/server-updates/files/;
        default_type application/gzip;
        add_header X-Content-Type-Options nosniff always;
    }

    location / {
        proxy_pass http://127.0.0.1:8008;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}
NGINX
ln -sfn /etc/nginx/sites-available/fedmes /etc/nginx/sites-enabled/fedmes
install -o root -g fedmes -m 0640 /etc/nginx/sites-available/fedmes /etc/fedmes/nginx-fedmes.conf
rm -f /etc/nginx/sites-enabled/default

echo "[8/10] Закрытие клиентских артефактов"
chown -R fedmes:fedmes /var/lib/fedmes
chmod 0700 /var/lib/fedmes /var/lib/fedmes/updates /var/lib/fedmes/updates/files
find /var/lib/fedmes/updates/files -type f -exec chmod 0600 {} +
find /var/lib/fedmes/server-updates -type d -exec chmod 0755 {} +
find /var/lib/fedmes/server-updates/files -type f -exec chmod 0644 {} +

echo "[9/10] Запуск и проверки"
nginx -t
systemctl daemon-reload
systemctl enable --now nginx.service fedmes.service fedmes-update.service fedmes-maintainer.service
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:8008/health/live >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8008/health/live >/dev/null
curl -fsS http://127.0.0.1:8010/health >/dev/null
curl -fsS --tlsv1.3 --tls-max 1.3 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/health/live" >/dev/null
status="$(curl -sS -o /dev/null -w '%{http_code}' --tlsv1.3 --tls-max 1.3 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/updates/files/test.apk")"
[[ "$status" == "404" ]] || { echo "Публичный каталог обновлений не закрыт: HTTP $status" >&2; exit 1; }
/opt/fedmes/bin/fedmes-maintainer --once --auto-server-update=false

echo "[10/10] FedMes 1.0.6 установлен с нуля"
echo "Резервная копия: $BACKUP"
[[ $WIPE_DATA -eq 0 ]] && echo "Сообщения, медиа, аккаунты и доверенные устройства сохранены." || echo "Данные удалены по --wipe-data; резервная копия создана."
echo "Публичный /updates/files/ закрыт. Клиентские файлы выдаются только POST + Bearer + одноразовый билет на 3 минуты."
