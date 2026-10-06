#!/bin/bash
# One patch/settings implementation on every platform: the Rust engine.
set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin${PATH:+:$PATH}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
case "$(uname -s):$(uname -m)" in
  Darwin:arm64) release_name=antigravity-bypass-russia-macos-arm64 ;;
  Darwin:x86_64) release_name=antigravity-bypass-russia-macos-x64 ;;
  *) release_name=antigravity-bypass-russia ;;
esac
# A downloaded engine beside this launcher takes precedence over old builds.
if [[ -x "$script_dir/$release_name" ]]; then exec "$script_dir/$release_name" "$@"; fi
if [[ -f "$repo_root/Cargo.toml" ]]; then
  # Older instructions used sudo. Build as the invoking user so rustup can find
  # their toolchain and Cargo does not leave root-owned files in the checkout.
  if [[ "$(id -u)" == 0 ]]; then
    if [[ "${SUDO_UID:-}" =~ ^[1-9][0-9]*$ ]]; then
      exec /usr/bin/sudo -H -u "#$SUDO_UID" -- /bin/bash "$script_dir/$(basename -- "${BASH_SOURCE[0]}")" "$@"
    fi
  else
    cargo_bin="$(command -v cargo || true)"
    if [[ -z "$cargo_bin" ]]; then
      cargo_candidate="${CARGO_HOME:-${HOME:-}/.cargo}/bin/cargo"
      if [[ -x "$cargo_candidate" ]]; then
        cargo_bin="$cargo_candidate"
        export PATH="$(cd -- "$(dirname -- "$cargo_bin")" && pwd):$PATH"
      fi
    fi
    if [[ -n "$cargo_bin" ]]; then
      "$cargo_bin" build --release --locked --manifest-path "$repo_root/Cargo.toml"
    fi
  fi
fi
for engine in "$repo_root/target/release/antigravity-bypass-russia" "$script_dir/$release_name" "$repo_root/$release_name"; do
  if [[ -x "$engine" ]]; then exec "$engine" "$@"; fi
done
printf '%s\n' 'Rust engine not found. Download and run the standalone macOS launcher:' >&2
printf '%s\n' '  curl -fsSL https://github.com/vezlin1/antigravity-bypass-russia/releases/latest/download/unlock_and_restore.sh -o unlock_and_restore.sh && chmod +x unlock_and_restore.sh && ./unlock_and_restore.sh' >&2
printf '%s\n' 'Or install Rust (https://rustup.rs) and run this repository script without sudo. The engine requests administrator privileges when needed.' >&2
exit 1
