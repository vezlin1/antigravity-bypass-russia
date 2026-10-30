"""Package reviewed source files for a Mac owner to build a standalone launcher."""
import argparse
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def package(output):
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], cwd=ROOT).decode().splitlines()
    allowed = {'Cargo.toml', 'Cargo.lock', 'build.rs', 'LICENSE', 'README.md'}
    prefixes = ('src/', 'scripts/', 'tests/', 'assets/', '.cargo/', 'docs/releases/')
    selected = [name for name in names if name in allowed or name.startswith(prefixes)]
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(set(selected)):
            path = ROOT / name
            if not path.is_file() or path.is_symlink():
                raise ValueError('Expected regular source file: ' + name)
            info = zipfile.ZipInfo('antigravity-macos-builder/' + name)
            info.external_attr = (0o100755 if path.suffix in {'.sh', '.command'} else 0o100644) << 16
            data = path.read_bytes()
            if path.suffix in {'.sh', '.command'}:
                data = data.replace(b'\r\n', b'\n')
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr('antigravity-macos-builder/BUILD.txt', '''On your Mac, open Terminal in this folder and run:
  bash scripts/build_macos_release.command

Builder prerequisites (only on your Mac): Apple Command Line Tools,
Rust with rustup (https://rustup.rs), Python 3.9 or newer, internet access.
Full Xcode is not required. Install Command Line Tools using:
  xcode-select --install

Output: dist/macos-ready/unlock_and_restore.sh and SHA256SUMS.txt.
Distribute the generated .sh to users. It embeds both Apple Silicon and Intel
native engines and needs no Xcode, Rust, Python or build downloads at runtime.
Users can run: bash unlock_and_restore.sh

The builder runs tests and a read-only --version check. It does not apply
the bypass, change DNS/VPN settings, publish releases or create Git tags.
Do not distribute scripts/unlock_and_restore.sh from the source folder;
use the generated dist/macos-ready/unlock_and_restore.sh.
''')
    print(output)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    package(parser.parse_args().output.resolve())
