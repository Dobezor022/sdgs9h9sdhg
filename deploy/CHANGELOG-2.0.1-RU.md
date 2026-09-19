# FedMes 2.0.1 — build 20001

## Server
- Production backend перенесён с Go на Rust.
- Rust binaries: `fedmes-server`, `fedmes-qr`, `fedmes-update-server`, `fedmes-maintainer`.
- SQLite schema 14 сохранена без destructive migration.
- Rust build/test выполняется до остановки текущего сервера.
- Installer выполняет health validation и rollback runtime/config при неудачном переключении.
- Медиа загружается/выдаётся потоково; файл не держится целиком в RAM.
- Конкурентная запись одного media ID не может перезаписать существующий blob.
- `/api/v1/events` используется как long-poll event clock.
- Nginx использует upstream keepalive, TLS 1.3 и bounded request/connection limits.
- Update download остаётся закрытым: session auth + одноразовый HMAC ticket.

## Android / Huawei
- Включён secure-session JSON-null fix.
- Текстовое сообщение появляется локально сразу в состоянии PENDING.
- Composer не ждёт сетевой round-trip обычного сообщения.
- Ratchet commit сериализуется только внутри конкретного чата.
- Device roster кэшируется на 60 секунд и прогревается при открытии чата.
- Foreground sync переведён с 3-секундного polling на event-driven long poll.
- Успешные HTTP connections не закрываются принудительно, что позволяет reuse TCP/TLS соединений.
- Account Root/Vault bootstrap выполняется до запуска messaging там, где требуется первое устройство.

## Windows
- В базу включены исправления Windows R5: analyzers, FedUI2 DPI, recovery exception normalization, clean build outputs.
- Версия клиента: 2.0.1 / build 20001.

## Security
- Protocol generation: 4.
- Security Epoch: 1.
- Legacy OPAQUE/password UI скрыт в 2.0.1, а Rust legacy OPAQUE endpoints работают fail-closed.
- QR/device identity/recovery является поддерживаемым production admission flow.
- Собственная замена OPAQUE или самодельные криптографические примитивы не добавлялись.
