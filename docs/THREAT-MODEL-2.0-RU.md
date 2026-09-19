# Threat Model FedMes 2.0

## Считаем потенциально враждебными

Интернет-провайдера, Wi-Fi, DNS, reverse proxy/TLS termination, VPS, server database, object storage, media relay, push provider и update distribution server. Также рассматриваются украденный пароль, старая копия локальной БД, потерянное устройство и временная компрометация session state.

## Что должен выдержать FedMes

- Снятая копия server DB не раскрывает endpoint private keys или plaintext.
- TLS termination видит только уже encrypted FedMes capsules/media packets.
- Знание account password не позволяет самостоятельно добавить trusted device.
- Сервер не может незаметно добавить устройство без допустимого trust transition.
- Старый snapshot клиента обнаруживается rollback counters/epochs после завершения полной интеграции Vault 2.
- Replayed capsule/media packet не становится новым сообщением/кадром.
- Update CDN не способен изготовить допустимый release без offline signatures.

## Неустранимая граница

Полностью скомпрометированный активный endpoint (kernel/admin malware с доступом к экрану/микрофону/процессу) может получить данные, которые устройство обязано показать владельцу. Никакой E2EE не может одновременно отобразить plaintext пользователю и скрыть его от полностью захваченной ОС.

Также нельзя обещать математическую невидимость самого факта интенсивного обмена данными: длительный видеозвонок неизбежно имеет заметный объём трафика. Цель transport privacy — не раскрывать content/application semantics, убрать постоянные protocol identifiers и уменьшить точность traffic correlation без разрушения latency.
