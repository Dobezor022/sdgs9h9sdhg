#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || exec sudo -E bash "$0" "$@"

readonly CURRENT_BUILD="30000"
readonly ROOT_DIR="/root"
readonly CURRENT_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly -a PROTECTED_PREFIXES=(
  "/var/lib/fedmes"
  "/etc/fedmes"
  "/opt/fedmes"
)

apply=0
delete_backups=0

usage() {
  cat <<USAGE
Usage: sudo $0 [--apply] [--including-old-backups]

Without --apply this command only prints the deletion plan.
The current build $CURRENT_BUILD and FedMes runtime data are always preserved.
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --apply) apply=1 ;;
    --including-old-backups) delete_backups=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

is_protected() {
  local candidate="$1"
  local prefix
  for prefix in "${PROTECTED_PREFIXES[@]}"; do
    [[ "$candidate" == "$prefix" || "$candidate" == "$prefix/"* ]] && return 0
  done
  return 1
}

safe_root_target() {
  local candidate="$1"

  [[ -n "$candidate" ]] || return 1
  [[ "$candidate" == "$ROOT_DIR/"* ]] || return 1
  [[ "$candidate" != "$ROOT_DIR" ]] || return 1
  [[ "$candidate" != "$CURRENT_SCRIPT_DIR" ]] || return 1
  [[ "$candidate" != "$CURRENT_SCRIPT_DIR/"* ]] || return 1
  [[ "$(basename -- "$candidate")" != *"$CURRENT_BUILD"* ]] || return 1
  is_protected "$candidate" && return 1

  # Only direct children of /root are eligible. Do not follow symlinks.
  [[ "$(dirname -- "$candidate")" == "$ROOT_DIR" ]] || return 1
  [[ ! -L "$candidate" ]] || return 1
  return 0
}

declare -A seen=()
declare -a targets=()
add_target() {
  local candidate="$1"
  safe_root_target "$candidate" || return 0
  [[ -z "${seen[$candidate]:-}" ]] || return 0
  seen[$candidate]=1
  targets+=("$candidate")
}

while IFS= read -r -d '' candidate; do
  add_target "$candidate"
done < <(
  find "$ROOT_DIR" -maxdepth 1 -mindepth 1 -xdev \
    \( \
      -name 'FedMes-1.*' -o \
      -name 'FedMes-2.*' -o \
      -name 'fedmes-install-1.0.*' -o \
      -name 'fedmes-upload-1.0.*' -o \
      -name 'fedmes-release-1.0.*' -o \
      -name 'fedmes-legacy-bridge-build' -o \
      -name 'FedMes-1.0.3-Legacy-1.0.2-Bridge.zip' \
    \) \
    ! -name "*$CURRENT_BUILD*" \
    -print0
)

if [[ $delete_backups -eq 1 ]]; then
  newest_before="$(find "$ROOT_DIR" -maxdepth 1 -mindepth 1 -xdev -type d -name 'fedmes-before-*' -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2- || true)"
  newest_full="$(find "$ROOT_DIR" -maxdepth 1 -mindepth 1 -xdev -type d -name 'fedmes-full-backup-*' -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2- || true)"

  while IFS= read -r -d '' backup; do
    [[ "$backup" == "$newest_before" || "$backup" == "$newest_full" ]] && continue
    add_target "$backup"
  done < <(
    find "$ROOT_DIR" -maxdepth 1 -mindepth 1 -xdev -type d \
      \( -name 'fedmes-before-*' -o -name 'fedmes-upgrade-backup-*' -o -name 'fedmes-full-backup-*' \) \
      -print0
  )
fi

if [[ ${#targets[@]} -eq 0 ]]; then
  echo "No old FedMes release files were found."
  exit 0
fi

IFS=$'\n' targets=($(printf '%s\n' "${targets[@]}" | sort -u))
unset IFS

printf 'The following old release paths will be removed:\n'
printf '  %s\n' "${targets[@]}"

if [[ $apply -ne 1 ]]; then
  cat <<PREVIEW

Dry run only. Apply with:
  sudo $0 --apply

To also prune old backup directories while retaining the newest pre-upgrade
backup and newest full backup:
  sudo $0 --apply --including-old-backups
PREVIEW
  exit 0
fi

for target in "${targets[@]}"; do
  safe_root_target "$target" || {
    echo "Refusing unsafe deletion target: $target" >&2
    exit 1
  }
  rm -rf --one-file-system -- "$target"
done

cat <<DONE
Old FedMes release packages before build $CURRENT_BUILD were removed.
Preserved unconditionally:
  /var/lib/fedmes
  /etc/fedmes
  /opt/fedmes
  $CURRENT_SCRIPT_DIR
DONE
