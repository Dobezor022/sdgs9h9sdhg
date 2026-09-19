# FedMes 1.0.6 build 10015: установка Ubuntu 24.04

## Установка с сохранением данных

```bash
cd /root/FedMes-1.0.6-Ubuntu-24.04-x64-secure-10015
sudo ./clean-install-1.0.6.sh --preserve-data
```

Перед заменой программ создаётся копия `/root/fedmes-before-clean-1.0.6-<дата-время>`.
Сохраняются SQLite, пользователи, доверенные устройства, сообщения и медиа.

`--wipe-data` удаляет рабочую базу и медиа. После него старые QR и сессии недействительны.

## Проверка

```bash
systemctl status fedmes.service fedmes-update.service fedmes-maintainer.service --no-pager -l
curl -fsS http://127.0.0.1:8008/health/live; echo
curl -fsS http://127.0.0.1:8010/health; echo
nginx -t
```

Проверка миграции read cursor:

```bash
sqlite3 /var/lib/fedmes/fedmes.sqlite3 '.schema chat_read_cursors'
```

## Публикация клиентов 10015

На Windows после сборки цели `6 — Всё`:

```powershell
.\Build\Publish-Required-Update-To-Ubuntu.ps1 -ProjectRoot "C:\Users\STUDIO-PC\Pictures\androidconsole"
```

Скрипт публикует код `10015`, вычисляет SHA-256, ждёт update service и удаляет только
устаревшие Android/Windows client artifacts.

> В режиме `--preserve-data` уже опубликованные APK/EXE и `releases.json` сохраняются, поэтому действующий релиз не получает временный HTTP 503. Публикуйте 10015 только после успешной локальной сборки и проверки новых APK/EXE.

## Удаление старых релизов

```bash
sudo ./cleanup-old-fedmes-releases.sh
sudo ./cleanup-old-fedmes-releases.sh --apply
```

Удаляются старые каталоги/архивы 1.0.0–1.0.5 и сборки 1.0.6 без `10015`.
Рабочие `/var/lib/fedmes`, `/etc/fedmes`, `/opt/fedmes` и текущий пакет 10015 не удаляются.

## Сохранение уже опубликованных APK/EXE

При `--preserve-data` установщик не удаляет `/var/lib/fedmes/updates`. Это предотвращает HTTP 503 между заменой сервера и публикацией нового build. После успешной сборки 10015 запустите `Build/Publish-Required-Update-To-Ubuntu.ps1`; publisher атомарно заменит manifest и удалит старые клиентские файлы.

## Encrypted backup перед production update

Создайте age identity и recipient один раз, храните identity вне VPS:

```bash
age-keygen -o /root/fedmes-backup-identity.txt
age-keygen -y /root/fedmes-backup-identity.txt | sudo tee /etc/fedmes/backup-recipient.txt >/dev/null
sudo chmod 600 /root/fedmes-backup-identity.txt /etc/fedmes/backup-recipient.txt
```

Создайте и проверьте backup:

```bash
backup_path="$(sudo /usr/local/sbin/fedmes-backup-encrypted)"
sudo /usr/local/sbin/fedmes-verify-backup "$backup_path" /root/fedmes-backup-identity.txt
```

Скопируйте `.tar.age`, `.sha256` и identity на отдельный защищённый носитель. Не храните единственную identity на том же VPS.

## Проверка security migration 0012

```bash
sqlite3 /var/lib/fedmes/fedmes.sqlite3 'SELECT MAX(version) FROM schema_migrations;'
sqlite3 /var/lib/fedmes/fedmes.sqlite3 "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('account_security_state','encrypted_key_vaults','recovery_packages','device_provisioning_requests','crypto_migrations') ORDER BY name;"
```

Ожидаемая schema version: `12`.
