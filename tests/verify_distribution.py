"""Verify the files delivered to users, including both embedded native engines."""
import argparse
import base64
import gzip
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
parser.add_argument("--engines", required=True, type=Path)
parser.add_argument("--macos-only", action="store_true", help="Verify a local Mac build without Windows files")
parser.add_argument("--linux-only", action="store_true", help="Verify a local Linux build without Windows/Mac files")
args = parser.parse_args()
directory = args.directory
# Release files: antigravity-bypass-<system>[-<cpu>].
WINDOWS = "antigravity-bypass-windows.exe"
MACOS = "antigravity-bypass-macos.sh"
LINUX_X64 = "antigravity-bypass-linux-x64"
LINUX_ARM64 = "antigravity-bypass-linux-arm64"
DEB = "antigravity-bypass-linux-x64.deb"
payload_names = {WINDOWS, MACOS, LINUX_X64, LINUX_ARM64, DEB, "install.sh"}
if args.macos_only:
    payload_names = {"antigravity-bypass-russia-macos-arm64", "antigravity-bypass-russia-macos-x64", MACOS}
elif args.linux_only:
    payload_names = {LINUX_X64, LINUX_ARM64, DEB, "install.sh"}
assert {p.name for p in directory.iterdir()} == payload_names | {"SHA256SUMS.txt"}, "Unexpected or missing distribution files"

checksums = {}
for line in (directory / "SHA256SUMS.txt").read_text(encoding="ascii").splitlines():
    digest, name = line.split("  ", 1)
    assert name in payload_names and name not in checksums, "Unexpected or duplicate checksum entry"
    assert re.fullmatch("[0-9a-f]{64}", digest), "Invalid SHA-256"
    checksums[name] = digest
assert set(checksums) == payload_names, "Incomplete checksum manifest"
for name, digest in checksums.items():
    assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest, f"Checksum mismatch: {name}"

if not args.macos_only and not args.linux_only:
    exe = (directory / WINDOWS).read_bytes()
    assert exe[:2] == b"MZ", "Windows engine is not PE"
    pe = struct.unpack_from("<I", exe, 60)[0]
    assert exe[pe:pe + 4] == b"PE\0\0" and struct.unpack_from("<H", exe, pe + 4)[0] == 0x8664, "Expected a Windows x64 engine"
    assert exe == (args.engines / "antigravity-bypass-russia.exe").read_bytes(), "Windows engine changed during packaging"

if (directory / LINUX_X64).is_file():
    elf = (directory / LINUX_X64).read_bytes()
    assert elf[:4] == b"\x7fELF", "Linux engine is not ELF"
    assert elf[4] == 2, "Expected 64-bit ELF"
    assert elf[18:20] == b"\x3e\x00", "Expected x86-64 ELF"
    assert elf == (args.engines / "antigravity-bypass-russia-linux-x64").read_bytes(), "Linux engine changed during packaging"

if (directory / LINUX_ARM64).is_file():
    elf = (directory / LINUX_ARM64).read_bytes()
    assert elf[:4] == b"\x7fELF", "Linux ARM64 engine is not ELF"
    assert elf[4] == 2, "Expected 64-bit ELF"
    assert elf[18:20] == b"\xb7\x00", "Expected AArch64 ELF"
    assert elf == (args.engines / "antigravity-bypass-russia-linux-arm64").read_bytes(), "Linux ARM64 engine changed during packaging"

launcher = directory / MACOS
if not args.linux_only:
    script = launcher.read_bytes()
    assert b"\r" not in script, "macOS launcher must use LF"
    payloads = re.findall(rb"<<'ANTIGRAVITY_ENGINE'[^\n]*\n(.*?)\nANTIGRAVITY_ENGINE", script, re.S)
    assert len(payloads) == 2, "Both native Mac engines must be embedded"
    for payload, arch, cpu in zip(payloads, ["arm64", "x64"], [0x100000C, 0x1000007]):
        engine = gzip.decompress(base64.b64decode(payload, validate=False))
        assert struct.unpack_from("<II", engine) == (0xFEEDFACF, cpu), f"Wrong Mach-O architecture: {arch}"
        assert engine == (args.engines / f"antigravity-bypass-russia-macos-{arch}").read_bytes(), f"Embedded engine differs: {arch}"

bash = str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe") if os.name == "nt" else shutil.which("bash")
assert bash, "Bash is required for launcher syntax validation"
for shell_script in [directory / name for name in (MACOS, "install.sh") if name in payload_names]:
    assert b"\r" not in shell_script.read_bytes(), f"{shell_script.name} must use LF"
    subprocess.run([bash, "-n", str(shell_script.resolve())], check=True, timeout=10)
print("PASS: exact distribution, SHA-256, native engine payloads and shell syntax")
