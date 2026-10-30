"""Package an already-built release; never publish or modify installed software."""
import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64-pc-windows-msvc": ("windows-x64", "antigravity-bypass-russia.exe", "unlock_and_restore.ps1"),
    "aarch64-apple-darwin": ("macos-arm64", "antigravity-bypass-russia-macos-arm64", "unlock_and_restore.sh"),
    "x86_64-apple-darwin": ("macos-x64", "antigravity-bypass-russia-macos-x64", "unlock_and_restore.sh"),
    "x86_64-unknown-linux-gnu": ("linux-x64", "antigravity-bypass-russia-linux-x64", "unlock_and_restore.sh"),
    "aarch64-unknown-linux-gnu": ("linux-arm64", "antigravity-bypass-russia-linux-arm64", "unlock_and_restore.sh"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error("Release binary does not exist")
    _, binary_name, wrapper = TARGETS[args.target]
    args.output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.binary, args.output / binary_name)
    shutil.copyfile(ROOT / "scripts" / wrapper, args.output / wrapper)
    print((args.output / binary_name).resolve())



if __name__ == "__main__":
    main()
