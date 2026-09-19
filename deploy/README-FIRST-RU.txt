FedMes 3.0.0 PRODUCTION SOURCE / build 30000

Production backend: Rust. Go server binaries are not part of the active backend.
Ubuntu: use clean-install-3.0.0.sh (default preserves /var/lib/fedmes).
The installer compiles the pinned Rust server and runs cargo test before replacing the active service.
Android Normal / Huawei / Windows clients are built by the root Build scripts.
Design contract: FedMes 2026 / Bridge 1.9 freeze19 inventory, sequence 682.
See ../docs/CLEAN-INSTALL-3.0.0-UBUNTU-RU.md, CHANGELOG-3.0.0-RU.md and VALIDATION-3.0.0-30000-RU.txt.

Security note: legacy RFC9807 OPAQUE/password endpoints remain intentionally fail-closed until a Rust implementation is interoperability-validated. QR/device/recovery paths remain the supported production authentication path.

Build-environment note: this source release must still be compiled on the documented Windows/Ubuntu build hosts. A source validation PASS is not a substitute for APK/EXE/cargo compilation on those hosts.
