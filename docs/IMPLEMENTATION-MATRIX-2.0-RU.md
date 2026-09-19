# FedMes 2.0 — Implementation Matrix

Legend: IMPLEMENTED = code exists; CONNECTED = used by an application path; VALIDATED = tested/built in the current environment; GATE = required before rollout.

| Area | Status | Notes |
|---|---|---|
| security2 identity / X25519 / Ed25519 | IMPLEMENTED + VALIDATED | standalone Go tests pass |
| TrustState hash chain / generation validation | IMPLEMENTED + VALIDATED | standalone Go tests pass |
| admission request/code/quorum primitives | IMPLEMENTED + VALIDATED | core primitives present; full UX wiring is a gate |
| directional message ratchet | IMPLEMENTED + VALIDATED | transactional receive commit |
| healing / fresh entropy rekey | IMPLEMENTED + VALIDATED | standalone tests pass |
| replay window | IMPLEMENTED + VALIDATED | message/media tests pass |
| file roots/chunk AEAD | IMPLEMENTED + VALIDATED | standalone tests pass |
| call root/media micro-epoch packet crypto | IMPLEMENTED + VALIDATED | crypto layer only |
| Go gomobile/worker FSA2 bridge | IMPLEMENTED | wrapper type-check path validated separately; full Go 1.25 build gate remains |
| Android FSA2 local protected state | IMPLEMENTED | target build gate remains |
| Windows FSA2 protected state | IMPLEMENTED | target build gate remains |
| Android blind object client | IMPLEMENTED | Fsa2MessageEngine exists; default MessagingRepository cutover remains a gate |
| Windows blind object client | IMPLEMENTED | Fsa2MessageEngine exists; default repository cutover remains a gate |
| server blind object tables/API | IMPLEMENTED | full server target build/test gate remains |
| server realtime in-memory relay | IMPLEMENTED | encrypted frame relay; media capture/codec integration remains a gate |
| Android realtime stream transport | IMPLEMENTED | transport only; full audio/video call engine not complete |
| Windows realtime stream transport | IMPLEMENTED | transport only; full audio/video call engine not complete |
| native Android audio/video call capture/render | GATE | not complete in this package |
| native Windows audio/video call capture/render | GATE | not complete in this package |
| call UI / group-call membership / screen-share integration | GATE | architecture specified, not production-complete |
| FedUI2 Android foundation | IMPLEMENTED | existing full screens still legacy Compose/Material shell |
| FedUI2 Windows renderer foundation | IMPLEMENTED | existing full screens still legacy WPF shell |
| complete FedUI2 migration | GATE | must be completed before claiming custom UI is finished |
| no-log server runtime default | IMPLEMENTED | io.Discard unless explicit FEDMES_DEV_LOGS=1 |
| no-log Nginx/systemd production install | IMPLEMENTED | 2.0 install script |
| 2.0 build tools | IMPLEMENTED + VALIDATED | tools tests pass; Linux/Windows builder executables rebuilt |
| Android target build | GATE | Android SDK unavailable in current environment |
| Windows target build | GATE | .NET SDK unavailable in current environment |
| server target build | GATE | required Go 1.25 toolchain/dependencies unavailable offline here |
| non-exportable long-lived key handles | GATE | current bridge still serializes some private material during creation/import |
| out-of-order/multipath message receive | GATE | current ratchet is strict in-order per route |
| dual offline production signing | GATE | no private release keys are bundled by design |
| external security review | GATE | required before production rollout |
