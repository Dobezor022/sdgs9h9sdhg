#!/usr/bin/env bash
set -Eeuo pipefail

BUNDLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ARCHIVE="${1:-$BUNDLE_DIR/server-source.tar.gz}"
OUTPUT="${2:-$BUNDLE_DIR/fedmes-server}"
GO_VERSION="1.26.5"
GO_ARCHIVE="go${GO_VERSION}.linux-amd64.tar.gz"
GO_SHA256="5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
TMP_GO=""
WORK=""
cleanup() {
  [[ -z "$TMP_GO" ]] || rm -rf "$TMP_GO"
  [[ -z "$WORK" ]] || rm -rf "$WORK"
}
trap cleanup EXIT

[[ -f "$SOURCE_ARCHIVE" ]] || { echo "Не найден исходный код сервера: $SOURCE_ARCHIVE" >&2; exit 1; }

version_ok() {
  command -v go >/dev/null 2>&1 || return 1
  local v
  v="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
  [[ "$(printf '%s\n' '1.25.0' "$v" | sort -V | head -n1)" == "1.25.0" ]]
}

if ! version_ok; then
  echo "Устанавливается Go $GO_VERSION для сборки FedMes…"
  TMP_GO="$(mktemp -d /tmp/fedmes-go.XXXXXX)"
  curl --fail --location --retry 4 --connect-timeout 20 \
    "https://go.dev/dl/$GO_ARCHIVE" -o "$TMP_GO/$GO_ARCHIVE"
  echo "$GO_SHA256  $TMP_GO/$GO_ARCHIVE" | sha256sum -c -
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$TMP_GO/$GO_ARCHIVE"
  ln -sfn /usr/local/go/bin/go /usr/local/bin/go
  ln -sfn /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  export PATH="/usr/local/go/bin:$PATH"
fi

WORK="$(mktemp -d /tmp/fedmes-server-build.XXXXXX)"
tar -xzf "$SOURCE_ARCHIVE" -C "$WORK"
SERVER_ROOT="$WORK/server"
CRYPTO_ROOT="$WORK/crypto-core"
SECURITY2_ROOT="$WORK/security2"
[[ -f "$SERVER_ROOT/go.mod" ]] || { echo "go.mod сервера не найден: $SERVER_ROOT/go.mod" >&2; exit 1; }
[[ -f "$CRYPTO_ROOT/go.mod" ]] || { echo "go.mod crypto-core не найден: $CRYPTO_ROOT/go.mod" >&2; exit 1; }
[[ -f "$SECURITY2_ROOT/go.mod" ]] || { echo "go.mod security2 не найден: $SECURITY2_ROOT/go.mod" >&2; exit 1; }

# Populate and verify module checksum files before compiling. This also
# makes the bundle robust when the packaging host could not access the public
# Go module proxy and therefore did not include crypto-core/go.sum.
export GOFLAGS=-mod=mod
(
  cd "$SECURITY2_ROOT"
  go test ./...
)
(
  cd "$CRYPTO_ROOT"
  go mod tidy
)
(
  cd "$SERVER_ROOT"
  go mod tidy
)

cd "$SERVER_ROOT"
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64
export GOFLAGS=-mod=readonly
go test ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o "$OUTPUT.tmp" ./cmd/fedmes-server
chmod 0755 "$OUTPUT.tmp"
mv -f "$OUTPUT.tmp" "$OUTPUT"
echo "Сервер собран: $OUTPUT"
sha256sum "$OUTPUT"
