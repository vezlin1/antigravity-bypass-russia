#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
if [[ "$(uname -s)" != Darwin ]]; then echo 'Run this builder on your Mac.' >&2; exit 1; fi
if ! xcrun --find clang >/dev/null 2>&1; then
  echo 'Builder prerequisite: install Apple Command Line Tools with xcode-select --install.' >&2
  exit 1
fi
export PATH="$HOME/.cargo/bin:$PATH"
for tool in cargo rustup python3; do
  command -v "$tool" >/dev/null || { echo "Builder prerequisite missing: $tool" >&2; exit 1; }
done
export MACOSX_DEPLOYMENT_TARGET=12.0
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo test --locked --bin antigravity-bypass-russia --test socket_tests
python3 tests/verify_macos_bundle.py
python3 tests/verify_wrappers.py
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --release --locked --target "$target"
  case "$target" in aarch64-*) arch=arm64 ;; *) arch=x86_64 ;; esac
  lipo -verify_arch "$arch" "target/$target/release/antigravity-bypass-russia"
  codesign --force --sign - "target/$target/release/antigravity-bypass-russia"
  codesign --verify --strict "target/$target/release/antigravity-bypass-russia"
done
mkdir -p dist/macos-ready
python3 scripts/bundle_macos_launcher.py \
  --arm64 target/aarch64-apple-darwin/release/antigravity-bypass-russia \
  --x64 target/x86_64-apple-darwin/release/antigravity-bypass-russia \
  --output dist/macos-ready/unlock_and_restore.sh
bash -n dist/macos-ready/unlock_and_restore.sh
bash dist/macos-ready/unlock_and_restore.sh --version
(cd dist/macos-ready && shasum -a 256 unlock_and_restore.sh > SHA256SUMS.txt)
printf '\nReady: %s/dist/macos-ready/unlock_and_restore.sh\nUsers need neither Xcode, Rust nor Python.\n' "$PWD"
