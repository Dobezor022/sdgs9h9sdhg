#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || exec sudo -E bash "$0" "$@"

BUNDLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DOMAIN="${FEDMES_DOMAIN:-}"
WIPE_DATA=0
STAGE=""
BACKUP=""
SWITCHED=0

usage() {
  cat <<'USAGE'
FedMes 3.0.0 Rust production installer

Required:
  export FEDMES_DOMAIN='fedmes.example.com'

Usage:
  sudo -E ./clean-install-3.0.0.sh [--preserve-data|--wipe-data]

Default: --preserve-data
The Rust suite is built and cargo-tested before the active service is stopped.
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --preserve-data) WIPE_DATA=0 ;;
    --wipe-data) WIPE_DATA=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный параметр: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$DOMAIN" ]] || { echo "FEDMES_DOMAIN обязателен." >&2; exit 2; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ && "$DOMAIN" != .* && "$DOMAIN" != *..* ]] || { echo "Некорректный FEDMES_DOMAIN." >&2; exit 2; }

required=(
  server-source.tar.gz build-rust-server-3.0-on-ubuntu.sh
  publish-release.sh publish-required-update.sh cleanup-old-fedmes-releases.sh
  releases.json backup-fedmes-encrypted.sh verify-fedmes-backup.sh restore-fedmes-encrypted.sh
)
for file in "${required[@]}"; do
  [[ -f "$BUNDLE_DIR/$file" ]] || { echo "В комплекте отсутствует $file" >&2; exit 1; }
done

CERT=""
KEY=""
LE_EMAIL="${FEDMES_LETSENCRYPT_EMAIL:-}"

find_valid_certificate() {
  local dir cert key
  for dir in "/etc/letsencrypt/live/$DOMAIN" /etc/letsencrypt/live/*; do
    [[ -d "$dir" ]] || continue
    cert="$dir/fullchain.pem"
    key="$dir/privkey.pem"
    [[ -s "$cert" && -s "$key" ]] || continue
    openssl x509 -in "$cert" -noout -checkhost "$DOMAIN" >/dev/null 2>&1 || continue
    openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null 2>&1 || continue
    CERT="$cert"
    KEY="$key"
    return 0
  done
  return 1
}

ensure_tls_certificate() {
  if find_valid_certificate; then
    echo "[tls] Использую действующий сертификат: $CERT"
    return 0
  fi

  echo "[tls] Сертификат для $DOMAIN отсутствует или скоро истекает. Получаю Let's Encrypt автоматически..."
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow 80/tcp >/dev/null
    ufw allow 443/tcp >/dev/null
  fi

  local nginx_was_active=0 rc=0
  if systemctl is-active --quiet nginx.service 2>/dev/null; then
    nginx_was_active=1
    systemctl stop nginx.service
  fi

  local certbot_args=(
    certonly --standalone --non-interactive --agree-tos
    --preferred-challenges http --cert-name "$DOMAIN" -d "$DOMAIN"
  )
  if [[ -n "$LE_EMAIL" ]]; then
    certbot_args+=(--email "$LE_EMAIL" --no-eff-email)
  else
    certbot_args+=(--register-unsafely-without-email)
  fi

  set +e
  certbot "${certbot_args[@]}"
  rc=$?
  set -e

  if [[ $nginx_was_active -eq 1 ]]; then
    systemctl start nginx.service || true
  fi

  [[ $rc -eq 0 ]] || { echo "Не удалось получить Let's Encrypt для $DOMAIN (certbot exit=$rc). Проверь DNS A/AAAA и доступность TCP/80." >&2; return "$rc"; }
  find_valid_certificate || { echo "Certbot завершился успешно, но валидный сертификат для $DOMAIN не найден." >&2; return 1; }
  echo "[tls] Сертификат готов: $CERT"
}

cleanup() {
  [[ -z "$STAGE" ]] || rm -rf -- "$STAGE"
}
restore_path() {
  local path="$1"
  rm -rf -- "$path"
  if [[ -e "$BACKUP$path" ]]; then
    mkdir -p "$(dirname -- "$path")"
    cp -a -- "$BACKUP$path" "$path"
  fi
}
rollback() {
  local code=$?
  trap - ERR
  if [[ $SWITCHED -eq 1 && -n "$BACKUP" && -d "$BACKUP" ]]; then
    echo "[rollback] Ошибка после переключения. Возвращаю предыдущий runtime/config..." >&2
    systemctl stop fedmes-maintainer.service fedmes-update.service fedmes.service 2>/dev/null || true
    restore_path /opt/fedmes
    restore_path /etc/fedmes
    restore_path /etc/systemd/system/fedmes.service
    restore_path /etc/systemd/system/fedmes-update.service
    restore_path /etc/systemd/system/fedmes-maintainer.service
    restore_path /etc/nginx/sites-available/fedmes
    rm -f /etc/nginx/sites-enabled/fedmes
    if [[ -e /etc/nginx/sites-available/fedmes ]]; then ln -sfn /etc/nginx/sites-available/fedmes /etc/nginx/sites-enabled/fedmes; fi
    systemctl daemon-reload || true
    nginx -t >/dev/null 2>&1 && systemctl restart nginx.service || true
    systemctl restart fedmes.service fedmes-update.service fedmes-maintainer.service 2>/dev/null || true
    echo "[rollback] Runtime/config восстановлены. /var/lib/fedmes не откатывался и не удалялся." >&2
  fi
  cleanup
  exit "$code"
}
trap rollback ERR
trap cleanup EXIT

export DEBIAN_FRONTEND=noninteractive
echo "[1/13] Production dependencies"
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl tar gzip nginx certbot acl python3 sqlite3 openssl age
if ! id fedmes >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/fedmes --shell /usr/sbin/nologin fedmes
fi

STAGE="$(mktemp -d /tmp/fedmes-3.0.0-stage.XXXXXX)"
echo "[2/13] Rust compile + tests BEFORE downtime"
"$BUNDLE_DIR/build-rust-server-3.0-on-ubuntu.sh" "$BUNDLE_DIR/server-source.tar.gz" "$STAGE/rust-bin"
for binary in fedmes-server fedmes-qr fedmes-update-server fedmes-maintainer; do
  "$STAGE/rust-bin/$binary" --version 2>&1 | grep -Fq '3.0.0' || { echo "Неверная версия $binary" >&2; exit 1; }
done
(cd "$STAGE/rust-bin" && sha256sum -c SHA256SUMS)

if [[ -s /var/lib/fedmes/fedmes.sqlite3 ]]; then
  schema="$(sqlite3 /var/lib/fedmes/fedmes.sqlite3 'SELECT COALESCE(MAX(version),0) FROM schema_migrations;' 2>/dev/null || echo invalid)"
  [[ "$schema" =~ ^[0-9]+$ ]] || { echo "Не удалось проверить текущую SQLite schema." >&2; exit 1; }
  (( schema <= 14 )) || { echo "База имеет schema $schema > 14; downgrade запрещён." >&2; exit 1; }
fi

echo "[3/13] TLS certificate / Let's Encrypt"
ensure_tls_certificate
systemctl enable --now certbot.timer >/dev/null 2>&1 || true
install -d -o root -g root -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/fedmes-nginx-reload <<'HOOK'
#!/usr/bin/env bash
set -e
nginx -t >/dev/null 2>&1
systemctl reload nginx.service
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/fedmes-nginx-reload

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/root/fedmes-before-3.0.0-$STAMP"
mkdir -p "$BACKUP"
backup_path() {
  local source="$1"
  [[ -e "$source" ]] || return 0
  local destination="$BACKUP$source"
  mkdir -p "$(dirname -- "$destination")"
  cp -a -- "$source" "$destination"
}
for path in \
  /opt/fedmes /etc/fedmes \
  /etc/systemd/system/fedmes.service \
  /etc/systemd/system/fedmes-update.service \
  /etc/systemd/system/fedmes-maintainer.service \
  /etc/nginx/sites-available/fedmes; do
  backup_path "$path"
done

if [[ $WIPE_DATA -eq 1 && -d /var/lib/fedmes ]]; then
  echo "[4/13] Full data backup requested by --wipe-data"
  backup_path /var/lib/fedmes
else
  echo "[4/13] Preserve-data mode: runtime/config backup created"
fi

# Downtime begins only here.
echo "[5/13] Stop active FedMes"
systemctl stop fedmes-maintainer.service fedmes-update.service fedmes.service 2>/dev/null || true
SWITCHED=1
if [[ -s /var/lib/fedmes/fedmes.sqlite3 && $WIPE_DATA -eq 0 ]]; then
  install -d -m 0700 "$BACKUP/var/lib/fedmes"
  sqlite3 /var/lib/fedmes/fedmes.sqlite3 ".backup '$BACKUP/var/lib/fedmes/fedmes.sqlite3'"
  chmod 0600 "$BACKUP/var/lib/fedmes/fedmes.sqlite3"
fi

if [[ $WIPE_DATA -eq 1 ]]; then rm -rf /var/lib/fedmes; fi
rm -rf /opt/fedmes
install -d -o root -g root -m 0755 /opt/fedmes/bin /var/www/fedmes
install -d -o root -g fedmes -m 0750 /etc/fedmes
install -d -o fedmes -g fedmes -m 0700 /var/lib/fedmes /var/lib/fedmes/media /var/lib/fedmes/maintenance
install -d -o fedmes -g fedmes -m 0700 /var/lib/fedmes/updates /var/lib/fedmes/updates/files

if [[ ! -s /etc/fedmes/update-ticket.key ]]; then
  umask 0077
  openssl rand -hex 32 > /etc/fedmes/update-ticket.key
fi
chown root:fedmes /etc/fedmes/update-ticket.key
chmod 0640 /etc/fedmes/update-ticket.key

cat > /etc/fedmes/fedmes.env <<ENV
FEDMES_ADDR=127.0.0.1:8008
FEDMES_PUBLIC_URL=https://$DOMAIN
FEDMES_DATA_DIR=/var/lib/fedmes
FEDMES_SHUTDOWN_TIMEOUT=20s
ENV
chown root:fedmes /etc/fedmes/fedmes.env
chmod 0640 /etc/fedmes/fedmes.env

echo "[6/13] Install Rust suite"
for binary in fedmes-server fedmes-qr fedmes-update-server fedmes-maintainer; do
  install -o root -g root -m 0755 "$STAGE/rust-bin/$binary" "/opt/fedmes/bin/$binary"
done
install -o root -g root -m 0755 "$BUNDLE_DIR/publish-release.sh" /usr/local/sbin/fedmes-publish-release
install -o root -g root -m 0755 "$BUNDLE_DIR/publish-required-update.sh" /usr/local/sbin/fedmes-publish-required-update
install -o root -g root -m 0755 "$BUNDLE_DIR/backup-fedmes-encrypted.sh" /usr/local/sbin/fedmes-backup-encrypted
install -o root -g root -m 0755 "$BUNDLE_DIR/verify-fedmes-backup.sh" /usr/local/sbin/fedmes-verify-backup
install -o root -g root -m 0755 "$BUNDLE_DIR/restore-fedmes-encrypted.sh" /usr/local/sbin/fedmes-restore-encrypted
install -o root -g root -m 0755 "$BUNDLE_DIR/cleanup-old-fedmes-releases.sh" /usr/local/sbin/fedmes-clean-old-releases

if [[ $WIPE_DATA -eq 1 || ! -s /var/lib/fedmes/updates/releases.json ]]; then
  install -o fedmes -g fedmes -m 0600 "$BUNDLE_DIR/releases.json" /var/lib/fedmes/updates/releases.json
fi
chown -R fedmes:fedmes /var/lib/fedmes
chmod 0700 /var/lib/fedmes /var/lib/fedmes/media /var/lib/fedmes/updates /var/lib/fedmes/updates/files
find /var/lib/fedmes/updates/files -type f -exec chmod 0600 {} +

cat > /etc/systemd/system/fedmes.service <<'UNIT'
[Unit]
Description=FedMes Rust family messenger server 3.0.0
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=fedmes
Group=fedmes
EnvironmentFile=/etc/fedmes/fedmes.env
ExecStart=/opt/fedmes/bin/fedmes-server serve
Restart=always
RestartSec=2s
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=true
StandardOutput=null
StandardError=null
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
Description=FedMes Rust authenticated update service 3.0.0
After=network-online.target fedmes.service
Wants=network-online.target
[Service]
Type=simple
User=fedmes
Group=fedmes
ExecStart=/opt/fedmes/bin/fedmes-update-server --addr 127.0.0.1:8010 --manifest /var/lib/fedmes/updates/releases.json --files-dir /var/lib/fedmes/updates/files --ticket-key /etc/fedmes/update-ticket.key
Restart=always
RestartSec=2s
UMask=0077
NoNewPrivileges=true
StandardOutput=null
StandardError=null
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
Description=FedMes Rust maintainer 3.0.0
After=network-online.target fedmes.service fedmes-update.service
Wants=network-online.target
[Service]
Type=simple
User=fedmes
Group=fedmes
ExecStart=/opt/fedmes/bin/fedmes-maintainer --interval 1m --update-interval 30m --auto-server-update=false --data-dir /var/lib/fedmes
Restart=always
RestartSec=10s
UMask=0077
NoNewPrivileges=true
StandardOutput=null
StandardError=null
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

cat > /var/www/fedmes/index.html <<'HTML'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title>FedMes</title><style>*{box-sizing:border-box}html,body{width:100%;height:100%;margin:0}body{display:grid;place-items:center;background:#f4f6f8}.loader{width:42px;height:42px;border:4px solid #d9dee5;border-top-color:#6b7280;border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}</style></head><body><div class="loader" aria-hidden="true"></div></body></html>
HTML
chmod 0644 /var/www/fedmes/index.html

echo "[7/13] Nginx low-latency proxy"
cat > /etc/nginx/sites-available/fedmes <<NGINX
limit_req_zone \$binary_remote_addr zone=fedmes_api:10m rate=30r/s;
limit_req_zone \$binary_remote_addr zone=fedmes_auth:10m rate=5r/s;
limit_conn_zone \$binary_remote_addr zone=fedmes_conn:10m;

upstream fedmes_backend {
    server 127.0.0.1:8008;
    keepalive 32;
}
upstream fedmes_update_backend {
    server 127.0.0.1:8010;
    keepalive 8;
}

server {
    listen 80;
    server_name $DOMAIN;
    access_log off;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    access_log off;
    error_log /var/log/nginx/fedmes-error.log warn;
    ssl_certificate $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols TLSv1.3;
    ssl_session_cache shared:FedMesTLS:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    client_max_body_size 270m;
    client_body_timeout 3600s;
    keepalive_timeout 75s;
    keepalive_requests 10000;
    limit_conn fedmes_conn 32;

    location = / {
        root /var/www/fedmes;
        try_files /index.html =404;
    }

    location = /_fedmes_update_auth {
        internal;
        proxy_pass http://fedmes_backend/api/v1/auth/validate;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Authorization \$http_authorization;
        proxy_set_header X-Forwarded-Proto https;
    }

    location = /api/v1/updates/check {
        auth_request /_fedmes_update_auth;
        auth_request_set \$fedmes_user \$upstream_http_x_fedmes_user;
        auth_request_set \$fedmes_device \$upstream_http_x_fedmes_device;
        proxy_pass http://fedmes_update_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Authorization \$http_authorization;
        proxy_set_header X-FedMes-Authenticated-User \$fedmes_user;
        proxy_set_header X-FedMes-Authenticated-Device \$fedmes_device;
        proxy_buffering off;
        add_header Cache-Control "private, no-store, max-age=0" always;
    }

    location = /api/v1/updates/download {
        limit_except POST { deny all; }
        auth_request /_fedmes_update_auth;
        auth_request_set \$fedmes_user \$upstream_http_x_fedmes_user;
        auth_request_set \$fedmes_device \$upstream_http_x_fedmes_device;
        proxy_pass http://fedmes_update_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Authorization \$http_authorization;
        proxy_set_header X-FedMes-Authenticated-User \$fedmes_user;
        proxy_set_header X-FedMes-Authenticated-Device \$fedmes_device;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        add_header Cache-Control "private, no-store, max-age=0" always;
    }

    location ^~ /updates/files/ { return 404; }

    location ~ ^/api/v1/(provisioning|auth)/ {
        limit_req zone=fedmes_auth burst=20 nodelay;
        proxy_pass http://fedmes_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 75s;
    }

    location /api/ {
        limit_req zone=fedmes_api burst=120 nodelay;
        proxy_pass http://fedmes_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location / {
        proxy_pass http://fedmes_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_read_timeout 75s;
    }
}
NGINX
ln -sfn /etc/nginx/sites-available/fedmes /etc/nginx/sites-enabled/fedmes
rm -f /etc/nginx/sites-enabled/default
install -o root -g fedmes -m 0640 /etc/nginx/sites-available/fedmes /etc/fedmes/nginx-fedmes.conf
nginx -t

echo "[8/13] Start Rust services"
systemctl daemon-reload
systemctl enable nginx.service fedmes.service fedmes-update.service fedmes-maintainer.service >/dev/null
systemctl restart nginx.service
systemctl start fedmes.service fedmes-update.service fedmes-maintainer.service

for _ in $(seq 1 40); do
  curl -fsS http://127.0.0.1:8008/health/live >"$STAGE/live.json" 2>/dev/null && break
  sleep 0.5
done
curl -fsS http://127.0.0.1:8008/health/live >"$STAGE/live.json"
python3 - "$STAGE/live.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1],encoding='utf-8'))
assert v.get('status')=='ok',v
assert v.get('server')=='rust',v
assert v.get('version')=='3.0.0',v
assert int(v.get('build'))==30000,v
PY
curl -fsS http://127.0.0.1:8008/health/ready >"$STAGE/ready.json"
python3 - "$STAGE/ready.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1],encoding='utf-8'))
assert v.get('status')=='ready',v
assert int(v.get('schema'))==14,v
PY
curl -fsS http://127.0.0.1:8010/health >"$STAGE/update.json"
python3 - "$STAGE/update.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1],encoding='utf-8'))
assert v.get('status')=='ok',v
assert v.get('server')=='rust',v
assert v.get('version')=='3.0.0',v
PY

echo "[9/13] TLS/public health"
curl -fsS --tlsv1.3 --tls-max 1.3 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/health/live" >"$STAGE/public-live.json"
python3 - "$STAGE/public-live.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1],encoding='utf-8'))
assert v.get('server')=='rust' and v.get('version')=='3.0.0',v
PY

status="$(curl -sS -o /dev/null -w '%{http_code}' --tlsv1.3 --tls-max 1.3 --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/updates/files/test.apk")"
[[ "$status" == "404" ]] || { echo "Публичный update directory открыт: HTTP $status" >&2; false; }

/opt/fedmes/bin/fedmes-maintainer --once --auto-server-update=false --data-dir /var/lib/fedmes

echo "[10/13] Verify services"
for svc in fedmes.service fedmes-update.service fedmes-maintainer.service nginx.service; do
  systemctl is-active --quiet "$svc" || { systemctl status "$svc" --no-pager -l >&2; false; }
done

if [[ -s /var/lib/fedmes/fedmes.sqlite3 ]]; then
  [[ "$(sqlite3 /var/lib/fedmes/fedmes.sqlite3 'SELECT MAX(version) FROM schema_migrations;')" == "14" ]] || { echo "Schema 14 validation failed" >&2; false; }
fi

echo "[11/13] Installed binary checksums"
(cd /opt/fedmes/bin && sha256sum fedmes-server fedmes-qr fedmes-update-server fedmes-maintainer)

echo "[12/13] Security state"
echo "Legacy OPAQUE/password endpoints are intentionally fail-closed in 3.0.0. Supported production admission: QR/device identity/recovery."

echo "[13/13] FedMes 3.0.0 Rust RELEASE installed"
echo "Backup: $BACKUP"
[[ $WIPE_DATA -eq 0 ]] && echo "Data preserved: /var/lib/fedmes" || echo "Data reset requested; previous data is in backup."
SWITCHED=0
