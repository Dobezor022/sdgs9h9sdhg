# FedMes 2.0.0 build 20000 — установка и сборка

Этот файл относится к packaging-fix от 18.09.2026.

## Ubuntu 24.04 x86_64

1. DNS A/AAAA домена FedMes должен вести на VPS.
2. До запуска installer должен существовать Let's Encrypt certificate в `/etc/letsencrypt/live/$FEDMES_DOMAIN/`.
3. Соберите Linux bundle на Windows/другой build host командой `Build\\fedmes-build.exe --root . linuxhttps`, либо используйте исправленный `deploy/` из source archive.
4. На VPS задайте `FEDMES_DOMAIN` и запускайте только с `sudo -E`, чтобы переменная сохранилась:

```bash
export FEDMES_DOMAIN='fedmes.example.com'
sudo -E ./clean-install-2.0.0.sh --preserve-data
```

Проверка:

```bash
systemctl status fedmes.service fedmes-update.service fedmes-maintainer.service --no-pager -l
curl -fsS http://127.0.0.1:8008/health/live; echo
curl -fsS http://127.0.0.1:8010/health; echo
nginx -t
sqlite3 /var/lib/fedmes/fedmes.sqlite3 'SELECT MAX(version) FROM schema_migrations;'
```

Ожидаемая schema version: 14.

## Android Normal / Huawei

Требования: Go 1.25+, JDK 21, Android SDK Platform 37, Build Tools 37.0.0, Android NDK (Side by side), PowerShell.

Release signing variables:

```powershell
$env:FEDMES_ANDROID_KEYSTORE = 'C:\FedMesSecrets\fedmes-release.jks'
$env:FEDMES_ANDROID_KEYSTORE_PASSWORD = '...'
$env:FEDMES_ANDROID_KEY_ALIAS = 'fedmes'
$env:FEDMES_ANDROID_KEY_PASSWORD = '...'
$env:ANDROID_SDK_ROOT = 'C:\Android\SDK'
$env:ANDROID_HOME = $env:ANDROID_SDK_ROOT
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-21'
```

Сборка:

```powershell
.\Build\android.ps1
.\Build\huawei.ps1
```

Outputs:
- `Build\android\normal\FedMes-normal.apk`
- `Build\android\huawei\harmonous2.0\FedMes-huawei.apk`

## Windows x64

Требования: Go 1.25+, .NET SDK 10, PowerShell.

```powershell
.\Build\windowsclient.ps1
```

Output:
- `Build\windowsclient\FedMes.Desktop.exe`

Перед production deployment подпишите EXE Authenticode-сертификатом и APK release keystore.
