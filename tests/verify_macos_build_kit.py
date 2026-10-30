"""Validate source kit contents and builder syntax without installing toolchains."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
bash = str(Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe') if os.name == 'nt' else shutil.which('bash')
with tempfile.TemporaryDirectory(prefix='mac-build-kit-') as temp:
    archive = Path(temp) / 'builder.zip'
    subprocess.run([sys.executable, str(ROOT / 'scripts/package_macos_build_kit.py'), '--output', str(archive)], check=True)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        prefix = 'antigravity-macos-builder/'
        for name in ['Cargo.lock', 'Cargo.toml', 'build.rs', 'src/main.rs', 'scripts/build_macos_release.command', 'scripts/bundle_macos_launcher.py', 'tests/upstream-versions.json', 'BUILD.txt']:
            assert prefix + name in z.namelist(), name
        assert not any('/target/' in name or '/.git/' in name or '/dist/' in name or '__pycache__' in name for name in z.namelist())
        builder = z.read(prefix + 'scripts/build_macos_release.command')
        assert b'\r' not in builder
        path = Path(temp) / 'build.command'
        path.write_bytes(builder)
        subprocess.run([bash, '-n', str(path)], check=True)
        for arch in [b'aarch64-apple-darwin', b'x86_64-apple-darwin']:
            assert arch in builder
print('PASS: Mac build kit contents, permissions metadata, source isolation and shell syntax')
