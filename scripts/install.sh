#!/bin/bash
# Antigravity Bypass Russia: Automated One-Line Installer for Linux and macOS.
# Usage: curl -fsSL https://raw.githubusercontent.com/vezlin1/antigravity-bypass-russia/main/scripts/install.sh | bash
set -euo pipefail

REPO="vezlin1/antigravity-bypass-russia"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64) BIN_NAME="antigravity-bypass-russia-linux-x64" ;;
      aarch64|arm64) BIN_NAME="antigravity-bypass-russia-linux-arm64" ;;
      *)
        printf 'Error: Unsupported Linux architecture: %s\n' "$ARCH" >&2
        exit 1
        ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64|x86_64) BIN_NAME="unlock_and_restore.sh" ;;
      *)
        printf 'Error: Unsupported macOS architecture: %s\n' "$ARCH" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    printf 'Error: Unsupported OS: %s (Windows users should use unlock_and_restore.ps1 or the .exe binary)\n' "$OS" >&2
    exit 1
    ;;
esac

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BIN_NAME}"

printf '==> Antigravity Bypass Russia Installer\n'
printf 'Detected OS: %s, Architecture: %s\n' "$OS" "$ARCH"
printf 'Downloading: %s\n' "$DOWNLOAD_URL"

TMP_DIR="$(mktemp -d)"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/antigravity-bypass-russia"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_DIR/antigravity-bypass-russia" "$DOWNLOAD_URL"
else
  printf 'Error: curl or wget is required to download.\n' >&2
  exit 1
fi

chmod +x "$TMP_DIR/antigravity-bypass-russia"

# Determine target install directory
if [[ -n "${AG_BYPASS_INSTALL_DIR:-}" ]]; then
  INSTALL_DIR="$AG_BYPASS_INSTALL_DIR"
  USE_SUDO=0
  mkdir -p "$INSTALL_DIR"
elif [[ -w "/usr/local/bin" ]]; then
  INSTALL_DIR="/usr/local/bin"
  USE_SUDO=0
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  INSTALL_DIR="/usr/local/bin"
  USE_SUDO=1
elif [[ "$(id -u)" -eq 0 ]]; then
  INSTALL_DIR="/usr/local/bin"
  USE_SUDO=0
else
  INSTALL_DIR="${HOME}/.local/bin"
  USE_SUDO=0
  mkdir -p "$INSTALL_DIR"
fi

TARGET="${INSTALL_DIR}/antigravity-bypass-russia"
ALIAS_TARGET="${INSTALL_DIR}/ag-bypass"

printf 'Installing to: %s\n' "$TARGET"
if [[ "$USE_SUDO" -eq 1 ]]; then
  sudo cp "$TMP_DIR/antigravity-bypass-russia" "$TARGET"
  sudo chmod 755 "$TARGET"
  sudo ln -sf "$TARGET" "$ALIAS_TARGET"
else
  cp "$TMP_DIR/antigravity-bypass-russia" "$TARGET"
  chmod 755 "$TARGET"
  ln -sf "$TARGET" "$ALIAS_TARGET"
fi

printf '\n\033[32m✔ Antigravity Bypass Russia успешно установлен!\033[0m\n'
printf 'Доступные команды:\n'
printf '  • antigravity-bypass-russia\n'
printf '  • ag-bypass\n\n'

# Check if INSTALL_DIR is in PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  printf '\033[33mПредупреждение: %s отсутствует в вашем $PATH.\033[0m\n' "$INSTALL_DIR"
  printf 'Добавьте в ~/.bashrc или ~/.zshrc:\n'
  printf '  export PATH="%s:$PATH"\n\n' "$INSTALL_DIR"
fi

printf 'Для запуска разблокировки выполните:\n'
printf '  ag-bypass\n'
