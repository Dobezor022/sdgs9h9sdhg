# Realtime FedMes 2.0

## Цель

Собственная задержка FedMes должна быть существенно меньше сетевого RTT/codec latency. Никаких public-key операций на каждом audio/video packet. Handshake/rekey используют agreement/signature primitives; media hot path — symmetric AEAD и заранее выделенные buffers.

## Pipeline

Audio: microphone → AEC/processing → encoder → FSA2 media encryption → realtime transport → authentication/replay → decrypt → jitter buffer → decoder → speaker.

Video: camera → processing → hardware encoder → FSA2 frame/packet encryption → fragmentation → realtime transport → reassembly → authentication → decrypt → hardware decoder → renderer.

Encryption расположен после codec, иначе encoded compression невозможна. Сервер не получает decoded/encoded plaintext frames.

## Media domains

Отдельные keys для Audio, Video, Screen, Control, Routing; отдельно по directions. CallRoot уникален для звонка. Media Micro-Epochs регулярно меняют epoch key. Каждый sequence выводит отдельный packet key.

## Transport

`/api/v4/stream` использует два независимых HTTPS streams: downstream GET и uplink POST с length-prefixed opaque frames. Relay держит bounded RAM queues. Никакой disk persistence. При overload старые кадры выталкиваются из очереди для сохранения realtime latency.

Этот adapter рассчитан на HTTP/2 reverse proxy с buffering disabled. Security Core от него не зависит; будущий QUIC/H3 adapter может использовать тот же media ciphertext/state.

## Latency rules

- Audio/control приоритетнее bulk/file.
- Message/file queues не блокируют realtime queues.
- Никаких unbounded queues.
- Никакого server-side transcoding/decryption.
- Network migration меняет transport route, а не CallRoot.
- Invalid packets не изменяют crypto/replay state.
