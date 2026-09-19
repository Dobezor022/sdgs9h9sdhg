#!/usr/bin/env bash
set -Eeuo pipefail
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$DIR/FedMes-server-update-2.0.0.tar.gz}"
for f in fedmes-server fedmes-update-server fedmes-maintainer; do
  [[ -x "$DIR/$f" ]] || { echo "Не найден $DIR/$f" >&2; exit 1; }
done
WORK="$(mktemp -d /tmp/fedmes-update-bundle.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
cp "$DIR/fedmes-server" "$DIR/fedmes-update-server" "$DIR/fedmes-maintainer" "$WORK/"
(cd "$WORK" && sha256sum fedmes-server fedmes-update-server fedmes-maintainer > SHA256SUMS)
tar -C "$WORK" -czf "$OUT" fedmes-server fedmes-update-server fedmes-maintainer SHA256SUMS
echo "$OUT"
sha256sum "$OUT"
