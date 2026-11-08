"""Check both payloads, argument forwarding and failure status without running a patch."""
import base64
import gzip
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from bundle_macos_launcher import bundle

arm = b'#!/usr/bin/env bash\nprintf "arm64\\n"\nprintf "%s\\n" "$@"\nexit 7\n'
x64 = arm.replace(b"arm64", b"x86_64")
script = bundle(arm, x64)
payloads = re.findall(r"<<'ANTIGRAVITY_ENGINE'[^\n]*\n(.*?)\nANTIGRAVITY_ENGINE", script, re.S)
assert [gzip.decompress(base64.b64decode(p)) for p in payloads] == [arm, x64]
def find_bash():
    if os.name != "nt":
        return shutil.which("bash")
    for candidate in [
        Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe",
        Path(os.environ.get("USERPROFILE", "")) / "scoop/apps/git/current/bin/bash.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Git/bin/bash.exe",
    ]:
        if candidate.is_file():
            return str(candidate)
    which = shutil.which("bash")
    if which:
        return which
    git = shutil.which("git")
    if git:
        for sub in ["bin/bash.exe", "usr/bin/bash.exe"]:
            candidate = Path(git).resolve().parent.parent / sub
            if candidate.is_file():
                return str(candidate)
    return None

bash = find_bash()
assert bash and Path(bash).is_file(), "Bash is required to verify the release launcher"
with tempfile.TemporaryDirectory(prefix="ag-bundle-test-") as temp:
    root = Path(temp)
    launcher = root / "unlock_and_restore.sh"
    arm_path, x64_path = root / "arm64", root / "x64"
    arm_path.write_bytes(arm)
    x64_path.write_bytes(x64)
    # Exercise the actual CLI writer on the interpreter running the test. An
    # in-memory bundle() check missed write_text(newline=...) on Python 3.9.
    subprocess.run([sys.executable, str(ROOT / "scripts/bundle_macos_launcher.py"),
                    "--arm64", str(arm_path), "--x64", str(x64_path),
                    "--output", str(launcher)], check=True, timeout=10)
    assert launcher.read_bytes() == script.encode("utf-8")
    assert b"\r" not in launcher.read_bytes()
    if os.name != "nt":
        assert launcher.stat().st_mode & 0o111 == 0o111
    subprocess.run([bash, "-n", str(launcher)], check=True, timeout=10)
    for arch in ["arm64", "x86_64"]:
        environment = root / "test-env.sh"
        environment.write_bytes((
            f'uname() {{ if [[ "$1" == -s ]]; then echo Darwin; else echo {arch}; fi; }}\n'
            # Test the real decoder on the host with its supported flag.
            + ('base64() { command base64 -d; }\n' if sys.platform != 'darwin' else '')
        ).encode("utf-8"))
        env = dict(os.environ, BASH_ENV=environment.as_posix(), MSYS_NO_PATHCONV="1", PATH="")
        result = subprocess.run([bash, str(launcher), "--check", "space and кириллица"], env=env,
                                capture_output=True, encoding="utf-8", timeout=10)
        assert result.returncode == 7, result
        assert result.stdout.splitlines() == [arch, "--check", "space and кириллица"], result
print("PASS: macOS bundle payloads, shell syntax, both architectures, arguments and exit status")
