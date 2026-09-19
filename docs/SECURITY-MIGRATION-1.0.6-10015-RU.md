# FedMes 1.0.6 build 10015: безопасная миграция

## Правило обновления

Используйте только:

```bash
sudo ./clean-install-1.0.6.sh --preserve-data
```

Миграции 0011, 0012 и 0013 аддитивны. Они не удаляют сообщения, медиа, устройства или старые ciphertext. `--wipe-data` предназначен только для осознанного полного сброса и не применяется при обновлении.

## Порядок перехода

1. Создать encrypted backup и выполнить `verify-fedmes-backup.sh`.
2. Установить server 10015 с dual-read legacy/v2.
3. Обновить одно доверенное устройство пользователя.
4. Создать Account Root Key, Recovery Key, encrypted vault и OPAQUE enrollment.
5. Подключить тестовое новое устройство, подтвердить его и проверить восстановление истории.
6. Включить crypto version 2 для новых сообщений.
7. Запустить bounded/resumable migration legacy messages/media.
8. Проверить progress, ciphertext hashes и отсутствие failed records.
9. Повторить для остальных пользователей.
10. Только после полного restore-test удалить legacy key из vault и установить `legacy_fmk_removed_at`.

## Migration 0013

Она добавляет OPAQUE attempts/continuations/results, recovery packages, ratchet bundles/one-time keys/sessions, Olm envelopes, Megolm sessions/key packages, message sequence reservations, room rotation events и client-verified message/media replacement tables. Existing topology и ciphertext сохраняются.

## Откат

До завершения crypto migration новый сервер остаётся совместимым с legacy ciphertext. Restore script сначала сохраняет текущие `/var/lib/fedmes` и `/etc/fedmes`, разворачивает staged snapshot, проверяет health и при ошибке возвращает исходное состояние. Не удаляйте backup до проверки чистого Android и чистого Windows-профиля.
