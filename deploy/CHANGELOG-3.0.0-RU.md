# FedMes 3.0.0 / build 30000

- Rust backend остаётся единственным production backend; сохранены protocol generation 4 и security epoch 1.
- Long-poll `/api/v1/events` получил bounded `timeout_ms`, признак `changed` и `server_time_ms`; добавлен authenticated `/api/v1/events/current`.
- Media upload остаётся streaming и теперь использует 512 KiB `BufWriter`; media-route разрешает encrypted payload до 260 MiB, application-level cap остаётся 256 MiB.
- Download stream использует 512 KiB reader capacity.
- HTTP hardening: HSTS, DENY framing, CSP `default-src 'none'`, no-referrer, no-store, per-response request id.
- Android/Huawei и Windows переведены на frozen Bridge 1.9/Figma semantic colors and compact chat geometry.
- Android получил FedUI 3 production components: ChatRowCompact, BottomBarV2, bubble, media player chrome и call-control tray.
- Windows chat list приведён к 360 px sidebar / 68 px compact rows / 54 px avatars; dark/light tokens синхронизированы с Figma.

- Android realtime: event cursor корректно принимает reset сервера после restart/snapshot; typing/presence вынесены в лёгкий 2-секундный ephemeral sync, чтобы статус не зависал после TTL.
- Текстовые сообщения отправляются optimistic: composer очищается сразу, pending-message заменяется серверной версией по стабильному message id без отката нового текста пользователя.
- Round-video shape является свойством конкретного зашифрованного сообщения (`round_shape`) и включён в Compose key; круг/квадрат больше не разделяют изменяемое состояние формы.
- Windows QR onboarding удерживает QR/error panel при transient network/error, повторный cleanup acknowledgement не заставляет сканировать QR заново после уже сохранённой сессии.
- Release gate усилен: builder binaries проверяются SHA-256, Rust source archive сверяется по содержимому с текущим `server/`, deploy/build copies обязаны быть byte-identical.
