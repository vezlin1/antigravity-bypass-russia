"""Bundle current Rust sources in one macOS launcher; builds on the user's Mac."""
import argparse
import base64
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import textwrap

ROOT = Path(__file__).resolve().parents[1]


def source_archive(root=ROOT):
    paths = [root / name for name in ("Cargo.toml", "Cargo.lock", "build.rs", "README.md")]
    paths += sorted((root / "src").rglob("*.rs"))
    paths += sorted(path for path in (root / "assets").rglob("*") if path.is_file())
    paths += [path for name in ("LICENSE", "LICENSE.md", "LICENSE.txt")
              if (path := root / name).is_file()]
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in paths:
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Source must be a regular file: {path}")
            data = path.read_bytes()
            member = tarfile.TarInfo(path.relative_to(root).as_posix())
            member.size = len(data)
            member.mode = 0o644
            member.mtime = 0
            archive.addfile(member, io.BytesIO(data))
    return gzip.compress(stream.getvalue(), mtime=0)


def bundle(payload):
    digest = hashlib.sha256(payload).hexdigest()
    encoded = "\n".join(textwrap.wrap(base64.b64encode(payload).decode("ascii"), 76))
    script = r'''#!/bin/bash
# Current Rust sources included; first launch builds natively on this Mac.
set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin${PATH:+:$PATH}"
if [[ "$(uname -s)" != Darwin ]]; then
  printf '%s\n' 'Этот скрипт предназначен для macOS.' >&2
  exit 1
fi
case "$(uname -m)" in arm64|x86_64) ;; *) printf '%s\n' 'Архитектура не поддерживается.' >&2; exit 1 ;; esac
if [[ "$(id -u)" == 0 ]]; then
  if [[ "${SUDO_UID:-}" =~ ^[1-9][0-9]*$ ]]; then
    exec /usr/bin/sudo -H -u "#$SUDO_UID" -- /bin/bash "${BASH_SOURCE[0]}" "$@"
  fi
  printf '%s\n' 'Запустите скрипт без sudo. Движок сам запросит права при необходимости.' >&2
  exit 1
fi
umask 077
cache_dir="${HOME:?}/Library/Caches/antigravity-bypass-russia/source-builds/@DIGEST@/$(uname -m)"
engine="$cache_dir/antigravity-bypass-russia"
hash_file="$cache_dir/engine.sha256"
if [[ -x "$engine" && -f "$hash_file" ]]; then
  actual_hash="$(shasum -a 256 < "$engine" | awk '{print $1}')"
  expected_hash="$(cat -- "$hash_file")"
  if [[ "$actual_hash" == "$expected_hash" ]]; then exec "$engine" "$@"; fi
fi
if ! xcode-select -p >/dev/null 2>&1; then
  printf '%s\n' 'Нужны инструменты разработчика Apple. Выполните xcode-select --install, завершите установку и повторите запуск.' >&2
  exit 1
fi
cargo_bin="$(command -v cargo || true)"
if [[ -z "$cargo_bin" ]]; then
  candidate="${CARGO_HOME:-$HOME/.cargo}/bin/cargo"
  if [[ -x "$candidate" ]]; then
    cargo_bin="$candidate"
    export PATH="$(cd -- "$(dirname -- "$candidate")" && pwd):$PATH"
  fi
fi
if [[ -z "$cargo_bin" ]]; then
  printf '%s\n' 'Нужен Rust: установите его по инструкции https://rust-lang.org/tools/install/ и повторите запуск.' >&2
  exit 1
fi
mkdir -p -- "$cache_dir"
work_dir="$(mktemp -d "$cache_dir/work.XXXXXXXX")"
cleanup() { rm -f -- "$work_dir/sources.tar.gz" "$work_dir/engine" "$work_dir/engine.sha256"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
base64 -D <<'ANTIGRAVITY_SOURCES' > "$work_dir/sources.tar.gz"
@PAYLOAD@
ANTIGRAVITY_SOURCES
archive_hash="$(shasum -a 256 < "$work_dir/sources.tar.gz" | awk '{print $1}')"
if [[ "$archive_hash" != '@DIGEST@' ]]; then
  printf '%s\n' 'Исходники повреждены; сборка отменена. Скопируйте скрипт заново.' >&2
  exit 1
fi
mkdir -- "$work_dir/source"
tar -xzf "$work_dir/sources.tar.gz" -C "$work_dir/source"
printf '%s\n' 'Собираю движок из включённых исходников. При первом запуске потребуется интернет для зависимостей Rust.' >&2
"$cargo_bin" build --release --locked --bin antigravity-bypass-russia --manifest-path "$work_dir/source/Cargo.toml" --target-dir "$cache_dir/target"
cp -- "$cache_dir/target/release/antigravity-bypass-russia" "$work_dir/engine"
chmod 700 "$work_dir/engine"
shasum -a 256 < "$work_dir/engine" | awk '{print $1}' > "$work_dir/engine.sha256"
mv -- "$work_dir/engine" "$engine"
mv -- "$work_dir/engine.sha256" "$hash_file"
cleanup
trap - EXIT INT TERM
exec "$engine" "$@"
'''
    return script.replace("@DIGEST@", digest).replace("@PAYLOAD@", encoded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(bundle(source_archive()), encoding="utf-8", newline="\n")
    args.output.chmod(0o755)
    print(args.output.resolve())


if __name__ == "__main__":
    main()
