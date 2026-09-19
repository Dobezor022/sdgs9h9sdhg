# FedMes 2.0 — Master Specification

Dobezor Studio / Family Local. Архитектурный baseline 2.0.0; актуальная реализация 2.0.1, build 20001, Security Epoch 1, protocol generation 4.

## 1. Назначение

FedMes 2.0 — закрытая endpoint-first communication platform для Windows и Android. Серверы, сеть, TLS termination, object storage, realtime relay и push infrastructure считаются недоверенными относительно plaintext. Безопасность не зависит от секретности исходников или формата протокола; приватными являются ключи и endpoint state.

## 2. Неподлежащие упрощению инварианты

- password != message decryption authority;
- server compromise != conversation compromise;
- TLS compromise != E2EE compromise;
- one device != whole account;
- User Root != message/file/call key;
- message key != conversation key;
- conversation key != blob key;
- audio key != video key != screen key != control key != routing key;
- transport credentials != content keys;
- update host != release signing authority;
- malformed/forged ciphertext never advances receive state;
- revoked/stale device never receives new generation secrets;
- protocol/source disclosure must not reveal plaintext;
- production infrastructure stores no persistent access/message/call logs.

## 3. Identity and device trust

Each account owns a User Root signing identity used only for trust/recovery transitions. Every installation creates a unique device signing key and X25519 agreement key locally. Device private keys are never generated, stored, or backed up by the server.

Login is split into Account Authentication and Device Admission. A correct password creates only a PROVISIONAL device. A trusted endpoint must approve the fresh device identity; approval is transcript-bound to the account auth, nonce, key material, Security Epoch and current Trust Generation. The server cannot promote a device by editing a database row.

Trust Constellation is a hash-linked signed state containing generation, security epoch, device set/statuses and parent hash. Equal-generation forks are security failures. Device states are PROVISIONAL, ACTIVE, QUARANTINED, REVOKED and EXPIRED.

## 4. New-device UX

Normal user flow remains short: install -> enter ID/password -> approve on an existing trusted device -> ready. Complexity remains inside the protocol. A nearby device can issue a one-time Continuity Capsule encrypted to the new Device Identity. History transfer is a separate permission; password alone never grants old history.

If no trusted device remains, recovery uses an independent recovery authority. Recovery creates a new generation and new device identity rather than resurrecting old device keys. Target production mode supports split recovery shares and quorum.

## 5. Conversation security

Application events are encrypted as whole objects. Sender identity, event kind, reply relation, logical timestamp, filename and media metadata belong inside authenticated ciphertext whenever routing does not strictly require them.

Each direction has an independent evolving RatchetState. A message key is derived per position and then destroyed. Receive state is transactional: state commits only after successful AEAD authentication. Periodic healing mixes fresh key agreement entropy and transcript binding into a new generation to provide recovery after temporary state compromise.

Replay, cross-conversation transfer, wrong generation, wrong route and wrong position are rejected by AAD/state checks.

## 6. Group security

Groups use membership generations/epochs rather than a permanent group key. Add/remove/revoke operations advance the group epoch and refresh authorized key material. New members do not receive historical media/message secrets unless an explicit history-transfer policy authorizes it.

Large group payloads can be encrypted once under a fresh ContentKey; access to the ContentKey is separately authorized to the current device set. This keeps per-device authorization without encrypting a large blob N times.

## 7. Blob/file domain

Every file owns a random FileRoot. MetadataKey, thumbnail key and per-chunk keys are domain-separated. Storage receives random object identifiers and ciphertext chunks only. Filename, MIME, duration, dimensions and thumbnails are encrypted metadata. Each chunk is independently authenticated, allowing resume without server plaintext.

Temporary voice/video/photo files must not be written to disk in plaintext. Local media cache, thumbnails, drafts and search indexes are encrypted at rest.

## 8. Realtime media domain

Calls are not implemented as chat messages. Call establishment is authenticated through an existing conversation/device trust relationship and creates a fresh CallRoot bound to call nonce, endpoint identities, Security Epoch, Trust Generation and handshake transcript.

CallRoot derives independent roots for audio-send, audio-receive, video-send, video-receive, screen-send, screen-receive, realtime-control and routing. Streams are divided into Media Micro-Epochs. Packets use short-lived per-packet keys and stateful replay windows. A forged packet cannot advance replay/key state.

The media pipeline encrypts after local encoding and decrypts before local decoding. Public-key operations occur during establishment/rekey/membership transitions, not per media packet. Hot paths use symmetric AEAD, bounded queues and preallocated buffers where platform implementation permits.

Network route migration is independent of CallRoot. Wi-Fi/LTE or relay migration must not end a call. Congestion control remains endpoint-side. Relay sees encrypted frames and opaque scheduling/routing handles, not codecs, participants or content semantics.

## 9. Latency architecture

Security must add negligible application latency compared with the physical network. Text send performs optimistic local commit, encryption and enqueue without waiting for the server. An active client keeps a warm transport path. Interactive events bypass bulk media/backups.

Scheduling classes are internally separated: realtime audio, realtime control, interactive text, realtime video, message media, background transfer and backup. External relay semantics use opaque temporary classes rather than application names.

No large file is allowed to head-of-line block an interactive message or audio packet. Realtime relay queues are bounded; stale frames are dropped rather than growing latency without bound.

## 10. Opaque transport fabric

The transport API accepts opaque objects/frames rather than message semantics. Application-visible labels such as FedMes, message, call, audio, video, username, chat name and device name must not be required in clear wire metadata.

The server blind object plane stores a SHA-256 digest of an unguessable route capability, ciphertext, length class, TTL and object id. It does not persist username, sender, recipient, chat, filename or event type for FSA2 objects.

Realtime plane uses bounded in-memory queues and no media persistence. The transport can be replaced without replacing endpoint cryptography. Standard network transports are used; the architecture does not depend on impersonating a third-party service.

Padding/size classes, aggregation and fragmentation reduce fine-grained metadata leakage, but FedMes does not claim to make bandwidth volume or IP connectivity physically invisible to a global observer.

## 11. Local Vault

Target hierarchy: VaultRoot -> IdentityWrapKey, MessageDBKey, SearchIndexKey, MediaCacheKey, DraftKey, SettingsKey and BackupKey. Platform secure storage wraps endpoint root material; it is not the security protocol itself.

App Lock must seal cryptographic state, close decrypted handles and clear sensitive render/media/key buffers where possible. It is not merely a PIN overlay. Sensitive recovery/admission screens use capture protection where available.

## 12. Updates and release trust

Production packages are signed independently of the update host. Update infrastructure stores signed artifacts but does not possess offline release private keys. Manifest includes app version/build, Security Epoch, package/binary hashes, minimum accepted epoch and compatibility data.

Target design uses two independent production authorities. Trusted devices can exchange release digests through E2EE; inconsistent binaries presented under the same release identity create RELEASE_FORK and block automatic update.

Rollback is rejected both for remote Security Epoch and local protected state.

## 13. No-logs production policy

New production paths write no persistent access, message, call, IP-history, User-Agent-history, request-body or media logs. Nginx access logging is disabled in the 2.0 installer. Server runtime slog goes to io.Discard by default; FEDMES_DEV_LOGS=1 is a deliberate development-only override. systemd services are configured with null stdout/stderr in the 2.0 install script.

Operational counters required for rate limiting/congestion/load remain ephemeral in RAM and disappear on restart. Security state required for protocol continuity is not an activity log.

## 14. FedUI 2

Windows and Android remain platform shells, not visual design systems. FedUI defines its own scene/components, layout rules, security indicators and dense information hierarchy. System APIs are retained only where reimplementing them would reduce security/accessibility: window/surface, IME, accessibility bridge, camera, microphone, hardware codecs, notifications, secure storage and OS lifecycle.

The visual language is compact, deterministic and high-density; it does not copy Material/Fluent or a specific messenger. Security Center and Device Room are first-class screens rather than hidden settings. Security Spine displays real verified trust state, not a decorative lock.

## 15. Backend separation

Target deployment separates Identity Plane, Blind Object Plane, Blob Plane and Realtime Relay logically, with optional process/host isolation. No single normal backend plane needs full identity + content + realtime knowledge.

## 16. Migration from 1.x

1.x remains a migration source. Legacy ciphertext is decrypted only on an already trusted endpoint, converted to 2.0 application objects and re-encrypted into the new Vault/security domains. The server never receives migration plaintext. No destructive wipe is required. Legacy writers are disabled only after successful validation/cutover.

## 17. Required acceptance tests before family production rollout

- full Android Normal and Huawei release builds;
- full Windows release build;
- Linux server build on the pinned Go toolchain;
- clean install and preserve-data upgrade on a copy of production data;
- device add/quarantine/revoke/expire/recovery tests;
- forged/replayed/reordered capsule corpus;
- rollback/fork/release-fork tests;
- multi-hour audio/video call soak with packet loss/network migration;
- fuzzing of every network/state parser;
- local Vault theft/rollback tests;
- update signing and rollback tests;
- independent review of cryptographic state machines and deployment.
