# FedMes 2.0.1 Rust — установка/обновление Ubuntu 24.04

FedMes 2.0.1 использует Rust backend. Go backend находится только в `legacy-reference` и production-службами не запускается.

## Обновление существующего FedMes 2.0.0

```bash
cd /root/FedMes-2.0.1-RELEASE/deploy
export FEDMES_DOMAIN='fedmes.xuanguang.su'
sudo -E ./clean-install-2.0.1.sh --preserve-data
```

`--preserve-data` используется по умолчанию и сохраняет `/var/lib/fedmes`.

Installer выполняет порядок:

1. Проверяет сертификат и bundle.
2. Устанавливает build/runtime dependencies.
3. Во временном каталоге запускает `cargo test --all-targets`.
4. Собирает четыре Rust binary в release mode.
5. Проверяет текущую SQLite schema; schema >14 блокируется как downgrade.
6. Только после успешной Rust-сборки останавливает активный FedMes.
7. Создаёт backup runtime/config и SQLite snapshot.
8. Переключает systemd на Rust binaries.
9. Проверяет local health, schema 14, Rust version 2.0.1, update service и публичный TLS 1.3 endpoint.
10. При ошибке после переключения автоматически возвращает предыдущий runtime/config.

Пользовательские данные при обычном `--preserve-data` installer не удаляет.

## Чистая установка

Если данные действительно нужно удалить:

```bash
export FEDMES_DOMAIN='fedmes.xuanguang.su'
sudo -E ./clean-install-2.0.1.sh --wipe-data
```

Перед wipe создаётся полный backup `/var/lib/fedmes`.

## Проверка

```bash
systemctl is-active fedmes.service
systemctl is-active fedmes-update.service
systemctl is-active fedmes-maintainer.service
systemctl is-active nginx.service

curl -fsS http://127.0.0.1:8008/health/live && echo
curl -fsS http://127.0.0.1:8008/health/ready && echo
curl -fsS http://127.0.0.1:8010/health && echo
```

`/health/live` должен содержать `"server":"rust"`, `"version":"2.0.1"`, `"build":20001`.

## QR

```bash
sudo -u fedmes /opt/fedmes/bin/fedmes-qr \
  --server-url 'https://fedmes.xuanguang.su' \
  --data-dir '/var/lib/fedmes' \
  --out-dir '/var/lib/fedmes/private-qr' \
  --ttl '15m' \
  --users grisha,papa
```

TTL больше 15 минут отклоняется.

## Публикация клиентов

```bash
sudo /usr/local/sbin/fedmes-publish-release \
  --normal /root/FedMes-normal.apk \
  --huawei /root/FedMes-huawei.apk \
  --windows /root/FedMes.Desktop.exe \
  --version 2.0.1 \
  --version-code 20001 \
  --minimum-code 20001 \
  --notes 'FedMes 2.0.1 build 20001'
```

## OPAQUE

В 2.0.1 legacy password/OPAQUE endpoints намеренно fail-closed и соответствующий UI скрыт. Это сделано вместо небезопасного самостоятельного переписывания PAKE. Production onboarding: QR + Device Identity + Recovery Key / trusted-device flow.
