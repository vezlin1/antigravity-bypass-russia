"""Check pinned official CLI fixtures; only disposable copies are patched."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = [
    ("1.2.10", "arm64", "1e43262d55f69e20bf4ba4f087252d65dd4ed37c0a980fae50a6bd5bc3637650"),
    ("1.2.14", "arm64", "a33fdf084ecd199df00694f35a243200a3efacb1f4f3adf04ca19d76f7f714c4"),
    ("1.2.14", "x64", "26ad647b3eea0c8a10a600a03a2d04135d31da04ef5110fb08ec6f08b9c9f0a7"),
]


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def fixture(root, version, arch, expected):
    folder = root / f"{version}-{arch}"
    binary = folder / "antigravity"
    if binary.is_file():
        if digest(binary) != expected:
            raise RuntimeError(f"Fixture checksum mismatch: {binary}")
        return binary
    folder.mkdir(parents=True, exist_ok=True)
    url = ("https://github.com/google-antigravity/antigravity-cli/releases/download/"
           f"{version}/agy_cli_mac_{arch}.tar.gz")
    print(f"Download official CLI {version} macOS {arch}", flush=True)
    request = urllib.request.Request(url, headers={"User-Agent": "antigravity-profile-regression"})
    with tempfile.TemporaryFile() as download:
        with urllib.request.urlopen(request, timeout=90) as response:
            shutil.copyfileobj(response, download)
        download.seek(0)
        with tarfile.open(fileobj=download, mode="r:gz") as archive:
            members = [m for m in archive.getmembers()
                       if m.isfile() and Path(m.name).name == "antigravity"]
            if len(members) != 1:
                raise RuntimeError("Expected exactly one CLI executable in the archive")
            # Read one regular member; never extract archive paths or symlinks.
            with archive.extractfile(members[0]) as source, binary.open("wb") as output:
                shutil.copyfileobj(source, output)
    if digest(binary) != expected:
        binary.unlink()
        raise RuntimeError(f"Official CLI checksum mismatch: {version} {arch}")
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, help="Optional verified fixture cache")
    parser.add_argument("--target", help="Cargo target used by CI")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ag-cli-fixtures-") as temporary:
        root = (args.fixture_dir or Path(temporary)).resolve()
        for version, arch, expected in FIXTURES:
            binary = fixture(root, version, arch, expected)
            environment = dict(os.environ)
            environment[f"AGY_{arch.upper()}_FIXTURE"] = str(binary)
            environment["AGY_X64_GATE_COUNT"] = "1"
            command = ["cargo", "test", "--locked", "--bin", "antigravity-bypass-russia"]
            if args.target:
                command.extend(["--target", args.target])
            test = "official_arm64_cli_fixture" if arch == "arm64" else "official_x64_cli_fixture"
            command.extend([test, "--", "--ignored", "--nocapture"])
            subprocess.run(command, cwd=ROOT, env=environment, check=True, timeout=300)
            print(f"PASS: official CLI {version} macOS {arch}", flush=True)

        pinned = json.loads((ROOT / "tests/upstream-versions.json").read_text())
        for platform, manifest in pinned["cli"].items():
            # macOS transaction tests invoke codesign, which cannot sign PE/ELF.
            # The Windows CI job covers those formats as well as both Mach-O builds.
            if sys.platform == "darwin" and not platform.startswith("darwin"):
                continue
            folder = root / (manifest["version"] + "-" + platform)
            folder.mkdir(parents=True, exist_ok=True)
            binary = folder / ("agy.exe" if platform.startswith("windows") else "agy")
            # Verify the complete official distribution before reading its executable.
            with tempfile.TemporaryFile() as download:
                request = urllib.request.Request(manifest["url"], headers={"User-Agent": "antigravity-profile-regression"})
                with urllib.request.urlopen(request, timeout=90) as response:
                    shutil.copyfileobj(response, download)
                download.seek(0)
                assert hashlib.file_digest(download, "sha512").hexdigest() == manifest["sha512"], platform
                download.seek(0)
                if platform.startswith("windows"):
                    with binary.open("wb") as output:
                        shutil.copyfileobj(download, output)
                else:
                    with tarfile.open(fileobj=download, mode="r:gz") as archive:
                        members = [m for m in archive.getmembers() if m.isfile() and Path(m.name).name in {"agy", "antigravity"}]
                        assert len(members) == 1, platform
                        with archive.extractfile(members[0]) as source, binary.open("wb") as output:
                            shutil.copyfileobj(source, output)
            arch = "arm64" if platform.endswith("arm64") else "x64"
            environment = dict(os.environ)
            environment[f"AGY_{arch.upper()}_FIXTURE"] = str(binary)
            environment["AGY_X64_GATE_COUNT"] = "1"
            command = ["cargo", "test", "--locked", "--bin", "antigravity-bypass-russia"]
            if args.target:
                command.extend(["--target", args.target])
            command.extend([f"official_{arch}_cli_fixture", "--", "--ignored", "--nocapture"])
            subprocess.run(command, cwd=ROOT, env=environment, check=True, timeout=300)
            print(f"PASS: official CLI {manifest['version']} {platform}", flush=True)


if __name__ == "__main__":
    main()
