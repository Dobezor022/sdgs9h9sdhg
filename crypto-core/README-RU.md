# FedMes Crypto Core 1.0.6 / 10015

Общее криптографическое ядро для Android Normal, Android Huawei, Windows и сервера.

- OPAQUE: `github.com/bytemare/opaque` v0.18.0, профиль RFC 9807.
- Личные чаты: Olm Double Ratchet через pure-Go `maunium.net/go/mautrix/crypto/goolm` v0.28.0.
- Семейная комната: Megolm через тот же crypto backend.
- Состояние ratchet передаётся клиенту только в зашифрованном pickle и сохраняется атомарно.
- Android собирает `fedmescrypto.aar` через gomobile.
- Windows собирает `fedmescrypto.dll` через `go build -buildmode=c-shared`.

Закрытые ключи pickle не входят в JSON ядра: их передаёт платформенное хранилище, защищённое Android Keystore или Windows DPAPI/CNG.
