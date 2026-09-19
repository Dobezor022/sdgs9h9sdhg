# FedMes 2.0 — Dobezor Studio / Family Local

FedMes 2.0 — закрытая коммуникационная система для Windows и Android. Архитектура 2.0 отделяет identity, device trust, messages, files, realtime media, local vault и transport. Сервер рассматривается как недоверенный relay/storage и не должен получать plaintext пользовательского содержимого.

Версия: **2.0.0**. Build: **20000**. Security Epoch: **1**. Protocol generation: **4**.

## Главное в 2.0

- `security2/`: новый FSA2 endpoint-security core на стандартных X25519, Ed25519, HKDF-SHA256 и AES-256-GCM.
- Trust Generation / Trust Constellation primitives и provisional device admission.
- Раздельные message ratchets, healing/rekey и replay protection.
- Отдельные file roots/chunk keys.
- Отдельный realtime call root, media micro-epochs и packet keys для audio/video/screen/control/routing.
- Blind object fabric: сервер хранит только route digest, ciphertext, TTL и delivery object id.
- Blind realtime stream: bounded RAM relay, не пишет media packets в БД.
- Windows и Android используют один crypto core через existing worker/gomobile bridge.
- FedUI 2 design foundation: собственные компоненты/renderer; legacy UI оставлен как migration shell до полного переноса экранов.
- Legacy 1.x crypto остаётся только для controlled migration/read path.

## Важный статус

Этот архив — **production-source candidate**, а не подписанный production release. В текущей рабочей среде успешно прогнаны unit tests нового `security2` и tools module, а новый `fedmes-build` собран для Linux/Windows. Здесь отсутствуют Android SDK, .NET SDK и Go 1.25+ dependency cache, поэтому Android/Windows/server target builds нельзя честно объявить проверенными в этой среде. См. `VALIDATION-2.0.0-20000-RU.txt`.

До фактической установки семье обязательны: target builds, code signing, clean install/upgrade test на копии данных, fuzzing parsers, call soak tests и независимый security review.

## С чего начинать

1. `docs/SECURITY-ARCHITECTURE-2.0-RU.md`
2. `docs/THREAT-MODEL-2.0-RU.md`
3. `docs/REALTIME-2.0-RU.md`
4. `docs/FEDUI2-DESIGN-SPEC-RU.md`
5. `docs/MIGRATION-1X-TO-2.0-RU.md`
6. `BUILD-FEDMES-2.0-RU.md`
7. `VALIDATION-2.0.0-20000-RU.txt`
