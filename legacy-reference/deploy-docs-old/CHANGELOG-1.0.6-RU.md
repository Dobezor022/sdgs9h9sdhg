# FedMes 1.0.6 build 10015

## Security, recovery и crypto v2

- Добавлена OPAQUE remote password registration/login/password change; пароль не отправляется серверу открытым.
- Неизвестный пользователь обслуживается через fake OPAQUE record без user enumeration.
- OPAQUE login выдаёт `AUTHENTICATED_NO_KEYS`, а не доступ к истории.
- Добавлены Account Root Key, отдельный Recovery Key, encrypted vault и staged local commit.
- Добавлен signed device approval с отдельными signing и key-agreement keys.
- Добавлен общий crypto-core: Olm для pairwise/device transport и Megolm для room sessions.
- Добавлены one-time keys, per-device packages, monotonic message sequence и replay protection.
- При revoke выполняется блокировка bundles/sessions и создаётся room key rotation.
- Добавлена resumable client-verified миграция legacy ciphertext в crypto version 2.
- Source ciphertext сохраняется до локальной проверки нового ciphertext и server commit.
- Добавлена migration `0013_opaque_ratchet_fmk_completion.sql`; она аддитивна и не удаляет историю.
- Добавлены encrypted backup, verification и rollback-safe restore.
- Production Android/Windows/update endpoints требуют HTTPS.

## Надёжность OPAQUE

- Encrypted KE2 continuation сохраняется в SQLite и переживает restart.
- Временная ошибка после KE3 не погашает login attempt.
- Повтор завершённого attempt возвращает сохранённый session result.
- Existing device login проверяет совпадение обоих public keys и revoke state.

## Версии

Все платформы: `1.0.6 / 10015`.

## Проверка выпуска

См. `VALIDATION-1.0.6-10015-RU.txt`. Полные Android/.NET/server builds должны завершиться на целевых Windows/Ubuntu до публикации production release.
