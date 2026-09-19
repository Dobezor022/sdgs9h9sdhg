# FedMes 3.0.0 production gates

## Passed inside the source-release workspace

- Project/version contract: 3.0.0 / build 30000 / protocol generation 4 / security epoch 1.
- Bridge 1.9 Figma contract pinned to freeze19 inventory sequence 682.
- Rust source lexical validation and forbidden-pattern checks.
- Clean SQLite migration replay through schema 14 and fixed family topology verification.
- Legacy API compatibility coverage: every required route from the reference server is present in Rust; extra 3.0 routes are additive.
- Shell syntax checks for deploy/build scripts.
- XAML/csproj XML parsing and Kotlin/C# delimiter sanity checks.
- FedMes semantic color/token parity checks between Android and Windows.
- `fedmes-build` 3.0.0 local Go unit test and Linux/Windows-x64 builder binary regeneration.
- Reproducible Rust `server-source.tar.gz` checksum in both `Build/linuxhttps` and `deploy`, plus byte-level source/content parity against the current `server/` tree.

## Must pass on the real build hosts before calling a binary release production

1. Ubuntu host: Rust toolchain install, `cargo test --release`, `cargo build --release`, clean or preserve-data install, systemd readiness probe and migration smoke test.
2. Windows build host: .NET 10 restore/test/publish for `FedMes.Desktop`, QR login regression, media player regression and update flow.
3. Android/Huawei build host: Gradle 9.5.1 / JDK 21 build, crypto AAR generation, Android normal APK and Huawei APK, instrumentation/device smoke tests.
4. Cross-device: text, photo, file, audio, round-video shapes, optimistic send, realtime delivery/read state, retry/offline recovery, media download/decrypt, QR device-link, recovery key and device revoke.
5. Physical Huawei 1200×800 class tablet: responsive layout, keyboard/insets, media orientation, background/resume and battery-policy behavior.
6. Calls: encrypted native media/signalling runtime is present on Android/Huawei (`AudioRecord`/`AudioTrack` + CameraX) and Windows (NAudio + OpenCvSharp) over the server blind realtime stream. Production acceptance still requires two-device and group-call permission/network/reconnect/background tests on real hardware.

The build pipeline is intentionally fail-closed: a source validation PASS and a pretty Figma screen are not substitutes for native compilation and device verification.
