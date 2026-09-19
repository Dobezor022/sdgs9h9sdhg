#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PUBLISHER="/usr/local/sbin/fedmes-publish-release"
[[ -x "$PUBLISHER" ]] || PUBLISHER="$SCRIPT_DIR/publish-release.sh"
exec "$PUBLISHER" \
  --version 3.0.0 \
  --version-code 30000 \
  --minimum-code 30000 \
  --notes 'FedMes 3.0.0 build 30000: Rust production backend, event-driven sync, optimistic low-latency messaging and Bridge 1.9 FedUI, realtime/media hardening and secure-session fixes.' \
  "$@"
