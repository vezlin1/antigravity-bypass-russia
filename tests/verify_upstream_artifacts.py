"""Smoke-test the pinned Google App, IDE and CLI on Linux x64 distributions."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from verify_app_artifacts import verify as verify_asar

ROOT = Path(__file__).resolve().parents[1]


def verify_digest(path, algorithm, expected):
    with path.open("rb") as source:
        actual = hashlib.file_digest(source, algorithm).hexdigest()
    if actual != expected:
        raise ValueError(f"{path.name}: {algorithm} mismatch")


def fixture(directory, name, artifact, algorithm):
    path = directory / name
    if path.is_file():
        verify_digest(path, algorithm, artifact[algorithm])
        return path

    with tempfile.TemporaryDirectory(dir=directory) as temporary:
        staged = Path(temporary) / name
        request = urllib.request.Request(
            artifact["url"], headers={"User-Agent": "antigravity-compatibility-check"}
        )
        with urllib.request.urlopen(request, timeout=120) as response, staged.open("wb") as output:
            shutil.copyfileobj(response, output)
        verify_digest(staged, algorithm, artifact[algorithm])
        staged.replace(path)
    return path


def extract_member(archive_path, destination, *suffixes):
    paths = tuple(f"/{suffix}" for suffix in suffixes)
    with tarfile.open(archive_path, "r|gz") as archive:
        for member in archive:
            if member.isfile() and f"/{member.name}".endswith(paths):
                with archive.extractfile(member) as source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output)
                return
    raise ValueError(f"{archive_path.name}: expected {' or '.join(suffixes)}")


def check_app(archive_path, pin, working):
    asar = working / "app.asar"
    extract_member(archive_path, asar, "resources/app.asar")
    verify_asar(asar, [pin])


def check_ide(archive_path, pin, working):
    product = working / "product.json"
    extract_member(archive_path, product, "resources/app/product.json")
    metadata = json.loads(product.read_text(encoding="utf-8"))
    if metadata.get("applicationName") != "antigravity-ide" or metadata.get("ideVersion") != pin["version"]:
        raise ValueError(f"{archive_path.name}: expected IDE {pin['version']} in release metadata")
    print(f"PASS: IDE {pin['version']} archive hash and version", flush=True)


def check_cli(archive_path, pin, working):
    binary = working / "agy"
    extract_member(archive_path, binary, "agy", "antigravity")
    with binary.open("rb") as source:
        header = source.read(20)
    if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
        raise ValueError(f"{archive_path.name}: expected a Linux x64 ELF executable")
    print(f"PASS: CLI {pin['version']} archive hash and executable format", flush=True)
    if sys.platform == "linux" and platform.machine() == "x86_64":
        binary.chmod(0o700)
        environment = dict(os.environ, HOME=str(working), XDG_CONFIG_HOME=str(working))
        result = subprocess.run(
            [binary, "--version"], cwd=working, env=environment, capture_output=True,
            text=True, check=True, timeout=30,
        )
        if pin["version"] not in result.stdout.split():
            raise ValueError(f"{archive_path.name}: unexpected CLI version: {result.stdout.strip()}")
        print(f"PASS: CLI {pin['version']} native --version", flush=True)


def check(directory, name, pins):
    app, ide, cli = pins["app"], pins["ide"], pins["cli"]["linux_amd64"]
    checks = (
        (f"app-{app['version']}-linux.tar.gz", app, "sha256", check_app),
        (f"ide-{ide['version']}-linux.tar.gz", ide, "sha256", check_ide),
        (f"cli-{cli['version']}-linux_amd64.tar.gz", cli, "sha512", check_cli),
    )
    with tempfile.TemporaryDirectory(prefix=f"ag-{name}-") as temporary:
        working = Path(temporary)
        for filename, pin, algorithm, verify in checks:
            verify(fixture(directory, filename, pin, algorithm), pin, working)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, help="Reuse locally downloaded pinned archives")
    args = parser.parse_args()
    pinned = json.loads((ROOT / "tests/upstream-versions.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="ag-upstream-fixtures-") as temporary:
        directory = (args.fixture_dir or Path(temporary)).resolve()
        directory.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=2) as executor:
            checks = [executor.submit(check, directory, name, pinned[name]) for name in ("current", "previous")]
            for future in checks:
                future.result()


if __name__ == "__main__":
    main()
