# Миграция FedMes 1.x → 2.0

1.x хранится в архиве как functional/migration base. FSA2 не должен смешивать state с Olm/Megolm/legacy AES envelopes.

Переход выполняется только на trusted endpoint: прочитать legacy ciphertext → локально decrypt → сериализовать новый Event → encrypt FSA2 → проверить local round-trip → commit migration marker. Server не получает migration plaintext.

До завершения migration legacy crypto разрешён только reader/migration code path. Новые события после account cutover должны создаваться только FSA2. Старые ciphertext удаляются только после проверки нового encrypted copy и backup.

Known Android null-key hotfix из ветки 1.0.8 применён к базовому `AndroidRatchetStore.kt` перед началом 2.0 изменений.
