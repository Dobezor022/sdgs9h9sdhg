# FedMes Security Architecture 2.0 (FSA2)

## 1. Инварианты

1. Компрометация VPS не должна раскрывать plaintext сообщений, файлов или звонков.
2. Пароль не является ключом расшифрования истории.
3. User Root не используется непосредственно для message/file/media encryption.
4. Каждое устройство имеет независимую identity и agreement key pair.
5. Один key domain не используется в другом domain.
6. Старый/отозванный device не получает ключи новых generations.
7. Невалидный ciphertext не изменяет receive state.
8. Replay не принимается как новое событие.
9. Transport можно заменить без изменения endpoint cryptography.
10. Production server не пишет persistent access/message/call logs.
11. Update server не должен владеть production release signing keys.
12. Знание исходников и wire specification само по себе не даёт plaintext.

## 2. Иерархия доверия

`UserRootPrivate/Public` подтверждает только изменения trust/recovery. На каждом устройстве создаются `DeviceIdentitySignKey`, `DeviceAgreementKey`, `DeviceVaultRoot`, transport/recovery bindings. Приватные device keys не создаются на сервере и не копируются между устройствами.

Новый вход разделён на Account Authentication и Device Admission. После правильного пароля устройство имеет статус `PROVISIONAL`, генерирует собственные ключи и формирует Admission Request. Действующий trusted device проверяет короткий human code и подписывает request. Только после quorum создаётся новая Trust Generation.

## 3. Trust Constellation

Trust State содержит UserRootID, Generation, SecurityEpoch, current devices/statuses и PreviousHash. Состояние имеет canonical binary representation и подпись. Устройства обмениваются Security Checkpoints. Разные состояния с одинаковым поколением трактуются как trust fork; критические trust/recovery операции блокируются до разрешения.

Статусы: PROVISIONAL, ACTIVE, QUARANTINED, REVOKED, EXPIRED. Revoke является криптографическим state transition, а не только SQL-флагом.

## 4. Conversation domain

Каждое направление разговора имеет независимый RatchetState: RootKey, ChainKey, Counter, Generation, Domain. Для каждого события выводится уникальный message key. После successful encrypt/decrypt выполняется commit следующего chain state. Receive state не продвигается до успешной AEAD-аутентификации.

Периодический healing смешивает fresh ECDH entropy и transcript binding с текущим root, создавая новое поколение и обнуляя старый chain state. Это ограничивает длительность компрометации после временной утечки состояния.

## 5. Opaque Capsule

Application Event целиком находится внутри ciphertext: sender, event type, reply relation, logical time, filenames и media metadata не обязаны присутствовать во внешнем transport envelope. Outer Capsule содержит только route capability, transport epoch, security generation, ratchet position, size class, nonce и ciphertext.

Capsule AAD связывает route, transport epoch, generation, position и size class. Перенос ciphertext в другой route/epoch/position не проходит authentication.

## 6. Blob domain

У файла отдельный FileRoot. Chunk key выводится из FileRoot + FileID + chunk index. Chunk authenticated отдельно, поэтому resume не требует расшифрования сервера. Filename, MIME, duration, thumbnail и фактическая семантика файла должны быть encrypted application metadata.

## 7. Realtime domain

CallRoot создаётся только из fresh call agreement и call transcript. Из него domain-separated keys: audio send/receive, video send/receive, screen send/receive, control и routing. Media epoch key дополнительно зависит от domain, direction, epoch и optional fresh rekey contribution. Каждый packet получает отдельный packet key.

Stateful media decrypt сначала выполняет AEAD authentication, затем replay-window commit. Поддельный пакет не способен занять replay slot. Старые media epochs отклоняются.

## 8. Blind backend

Новый `blind_routes` хранит только SHA-256 digest route capability, generation, TTL и quota. Связь route→username/device в таблице не хранится. `blind_objects` содержит object id, route digest, length class, ciphertext, hash и TTL. Нет chat id, sender, recipient, event type или filename.

Realtime relay не пишет frames в БД: только bounded in-memory queues. При перегрузке удаляется старый frame, а не накапливается latency.

## 9. Local Vault

Целевая структура: VaultRoot → IdentityWrapKey, MessageDBKey, SearchIndexKey, MediaCacheKey, DraftKey, SettingsKey, BackupKey. ОС используется как wrapping facility. При App Lock должны закрываться decrypted handles и очищаться temporary plaintext/key buffers.

## 10. Обновления

Production update manifest должен быть подписан offline authorities, иметь app version, build, SecurityEpoch, binary/package hash и minimum accepted epoch. Рекомендуется две независимые production signatures. Trusted devices могут обмениваться release digest через E2EE для обнаружения targeted release fork.

## 11. Криптографические примитивы FSA2 core

Текущая реализация `security2/` использует стандартную библиотеку Go: X25519 (ECDH), Ed25519 signatures, HKDF-SHA256 (explicit implementation), AES-256-GCM и `crypto/rand`. Собственный неизвестный cipher не используется. Новизна FedMes находится в state machine, separation, trust, transport и recovery architecture.
