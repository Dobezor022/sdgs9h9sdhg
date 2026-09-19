#!/usr/bin/env bash
set -Eeuo pipefail

BUNDLE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_ARCHIVE="${1:-$BUNDLE_DIR/server-source.tar.gz}"
OUTPUT_DIR="${2:-$BUNDLE_DIR/rust-bin}"
MIN_RUST="1.85.0"
MIN_CARGO="1.85.0"
WORK=""
cleanup() { [[ -z "$WORK" ]] || rm -rf "$WORK"; }
trap cleanup EXIT

[[ -f "$SOURCE_ARCHIVE" ]] || { echo "Не найден Rust source bundle: $SOURCE_ARCHIVE" >&2; exit 1; }

version_ge() {
  local have="$1" need="$2"
  [[ "$(printf '%s\n%s\n' "$need" "$have" | sort -V | head -n1)" == "$need" ]]
}

install_native_build_deps() {
  command -v cc >/dev/null 2>&1 && command -v pkg-config >/dev/null 2>&1 && return 0
  [[ ${EUID} -eq 0 ]] || { echo "Для установки Rust build dependencies запустите от root/sudo." >&2; exit 1; }
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev ca-certificates curl
}

activate_rustup_path() {
  export CARGO_HOME="${CARGO_HOME:-/root/.cargo}"
  export RUSTUP_HOME="${RUSTUP_HOME:-/root/.rustup}"
  export PATH="$CARGO_HOME/bin:$PATH"
  hash -r
}

rust_versions_ok() {
  command -v rustc >/dev/null 2>&1 || return 1
  command -v cargo >/dev/null 2>&1 || return 1
  local rv cv
  rv="$(rustc --version | awk '{print $2}')"
  cv="$(cargo --version | awk '{print $2}')"
  version_ge "$rv" "$MIN_RUST" && version_ge "$cv" "$MIN_CARGO"
}

install_modern_rust_if_needed() {
  install_native_build_deps
  activate_rustup_path

  if rust_versions_ok; then
    echo "[rust] существующий toolchain подходит: $(rustc --version); $(cargo --version)"
    return 0
  fi

  [[ ${EUID} -eq 0 ]] || { echo "Нужен rustc/cargo >= $MIN_RUST; запустите installer через sudo/root." >&2; exit 1; }
  echo "[rust] системный Rust отсутствует или слишком старый. Устанавливаю современный stable через rustup..."

  local tmp
  tmp="$(mktemp -d /tmp/fedmes-rustup.XXXXXX)"
  trap 'rm -rf "$tmp"; cleanup' EXIT
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    https://sh.rustup.rs -o "$tmp/rustup-init.sh"
  chmod 0700 "$tmp/rustup-init.sh"
  sh "$tmp/rustup-init.sh" -y --profile minimal --default-toolchain stable --no-modify-path
  rm -rf "$tmp"
  trap cleanup EXIT

  activate_rustup_path
  command -v rustup >/dev/null 2>&1 || { echo "rustup не установлен." >&2; exit 1; }
  rustup set profile minimal
  rustup toolchain install stable --profile minimal
  rustup default stable
  hash -r

  rust_versions_ok || {
    echo "После rustup нужен rustc/cargo >= $MIN_RUST, получено: $(rustc --version 2>/dev/null || echo missing); $(cargo --version 2>/dev/null || echo missing)" >&2
    exit 1
  }
  echo "[rust] активирован modern stable: $(rustc --version); $(cargo --version)"
}

install_modern_rust_if_needed
WORK="$(mktemp -d /tmp/fedmes-rust-build.XXXXXX)"
tar -xzf "$SOURCE_ARCHIVE" -C "$WORK"
SERVER_ROOT="$WORK/server"
[[ -f "$SERVER_ROOT/Cargo.toml" ]] || { echo "Cargo.toml не найден в server-source.tar.gz" >&2; exit 1; }

export CARGO_TERM_COLOR=never
export CARGO_NET_RETRY=5
export CARGO_HTTP_TIMEOUT=60
export RUST_BACKTRACE=1
cd "$SERVER_ROOT"

echo "[rust] rustc: $(rustc --version)"
echo "[rust] cargo: $(cargo --version)"
if [[ ! -f Cargo.lock ]]; then
  echo "[rust] Cargo.lock отсутствует в source bundle; создаю lock современным Cargo"
  cargo generate-lockfile
fi
cargo metadata --locked --no-deps --format-version 1 >/dev/null

echo "[rust] tests (locked)"
cargo test --locked --all-targets

echo "[rust] release build (locked)"
cargo build --locked --release --bins

mkdir -p "$OUTPUT_DIR.tmp"
rm -rf "$OUTPUT_DIR.tmp"/*
for binary in fedmes-server fedmes-qr fedmes-update-server fedmes-maintainer; do
  src="$SERVER_ROOT/target/release/$binary"
  [[ -x "$src" ]] || { echo "После cargo build отсутствует $binary" >&2; exit 1; }
  install -m 0755 "$src" "$OUTPUT_DIR.tmp/$binary"
  "$OUTPUT_DIR.tmp/$binary" --version 2>&1 | grep -Fq '3.0.0' || { echo "$binary имеет неверную версию" >&2; exit 1; }
done

rm -rf "$OUTPUT_DIR"
mv "$OUTPUT_DIR.tmp" "$OUTPUT_DIR"
(
  cd "$OUTPUT_DIR"
  cp "$SERVER_ROOT/Cargo.lock" ./Cargo.lock
  {
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "toolchain=$(rustup show active-toolchain 2>/dev/null || echo system)"
  } > BUILD-TOOLCHAIN.txt
  sha256sum fedmes-server fedmes-qr fedmes-update-server fedmes-maintainer Cargo.lock BUILD-TOOLCHAIN.txt > SHA256SUMS
  sha256sum -c SHA256SUMS
)
echo "Rust server suite 3.0.0 собран: $OUTPUT_DIR"
