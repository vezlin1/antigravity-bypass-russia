"""Check pinned official CLI fixtures; only disposable copies are patched."""
import argparse
from concurrent.futures import ThreadPoolExecutor
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
TEST_BINARY = None
FIXTURE_TESTS_PER_ARCH = 2
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


def verified_distribution(root, platform, manifest):
    expected = manifest["sha512"]
    directory = root / "distributions"
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / expected

    def verify(path):
        with path.open("rb") as source:
            actual = hashlib.file_digest(source, "sha512").hexdigest()
        if actual != expected:
            raise RuntimeError(f"Official CLI distribution checksum mismatch: {platform}")

    if archive.is_file():
        verify(archive)
        return archive

    request = urllib.request.Request(manifest["url"], headers={"User-Agent": "antigravity-profile-regression"})
    with tempfile.TemporaryDirectory(dir=directory) as staging:
        download = Path(staging) / "download"
        with urllib.request.urlopen(request, timeout=90) as response, download.open("wb") as output:
            shutil.copyfileobj(response, output)
        verify(download)
        download.replace(archive)
    return archive


def check_profile(binary, arch, target, label):
    environment = dict(os.environ)
    environment[f"AGY_{arch.upper()}_FIXTURE"] = str(binary)
    environment["AGY_X64_GATE_COUNT"] = "1"
    filters = [f"official_{arch}_cli_fixture", "--ignored", "--nocapture"]
    if TEST_BINARY:
        # The unit-test executable a CI build job produced: the same tests cargo would run.
        command = [str(TEST_BINARY), *filters]
    else:
        command = ["cargo", "test", "--locked", "--bin", "antigravity-bypass-russia"]
        if target:
            command.extend(["--target", target])
        command.extend(["--", *filters])
    print(f"Official CLI {label}", flush=True)
    result = subprocess.run(command, cwd=ROOT, env=environment, timeout=300, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    print(result.stdout, end="", flush=True)
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command)
    # Discovery and patch/rollback: a filter that silently matches nothing must not pass.
    if f"test result: ok. {FIXTURE_TESTS_PER_ARCH} passed;" not in result.stdout:
        raise RuntimeError(f"Expected {FIXTURE_TESTS_PER_ARCH} official {arch} fixture tests to run for {label}")
    print(f"PASS: official CLI {label}", flush=True)


def check_historical(root, target, version, arch, expected):
    binary = fixture(root, version, arch, expected)
    check_profile(binary, arch, target, f"{version} macOS {arch}")


def check_distribution(root, temporary, target, platform, manifest):
    folder = temporary / (manifest["version"] + "-" + platform)
    folder.mkdir(parents=True, exist_ok=True)
    binary = folder / ("agy.exe" if platform.startswith("windows") else "agy")
    # Verify the complete official distribution before reading its executable.
    archive_path = verified_distribution(root, platform, manifest)
    with archive_path.open("rb") as download:
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
    check_profile(binary, arch, target, f"{manifest['version']} {platform}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, help="Optional verified fixture cache")
    parser.add_argument("--target", help="Cargo target used by CI")
    parser.add_argument("--parallel", action="store_true", help="Check fixture groups concurrently")
    parser.add_argument("--jobs", type=int, default=2, help="Concurrent fixture groups with --parallel")
    parser.add_argument("--test-binary", type=Path,
                        help="Run this prebuilt unit-test executable instead of `cargo test`")
    args = parser.parse_args()
    global TEST_BINARY
    if args.test_binary:
        if not args.test_binary.is_file():
            parser.error(f"--test-binary {args.test_binary} does not exist")
        TEST_BINARY = args.test_binary.resolve()
    with tempfile.TemporaryDirectory(prefix="ag-cli-fixtures-") as directory:
        temporary = Path(directory)
        root = (args.fixture_dir or temporary).resolve()
        pinned = json.loads((ROOT / "tests/upstream-versions.json").read_text())
        checks = [(check_historical, (root, args.target, *item)) for item in FIXTURES]
        for platform, manifest in pinned["previous"]["cli"].items():
            # macOS transaction tests invoke codesign, which cannot sign PE/ELF.
            # The Windows CI job covers those formats as well as both Mach-O builds.
            if sys.platform != "darwin" or platform.startswith("darwin"):
                checks.append((check_distribution, (root, temporary, args.target, platform, manifest)))

        if args.parallel and (os.cpu_count() or 1) >= 2 and "AGY_X64_PATCH_OUTPUT" not in os.environ:
            with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as workers:
                results = [workers.submit(check, *params) for check, params in checks]
                for result in results:
                    result.result()
        else:
            for check, params in checks:
                check(*params)


if __name__ == "__main__":
    main()
