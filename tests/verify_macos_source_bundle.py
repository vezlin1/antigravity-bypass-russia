"""Verify the source launcher with fake Mac tools; never build or apply bypass."""
import base64
import gzip
import io
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from bundle_macos_sources import bundle, source_archive

payload = source_archive()
assert payload == source_archive(), "Source archive must be reproducible"
with tarfile.open(fileobj=io.BytesIO(gzip.decompress(payload))) as archive:
    members = archive.getmembers()
    assert all(m.isfile() and not Path(m.name).is_absolute() and ".." not in Path(m.name).parts for m in members)
    names = {m.name for m in members}
    expected = {p.relative_to(ROOT).as_posix() for p in (ROOT / "src").rglob("*.rs")}
    assert expected <= names
    assert {"Cargo.toml", "Cargo.lock", "build.rs", "README.md"} <= names
    for member in members:
        assert archive.extractfile(member).read() == (ROOT / member.name).read_bytes(), member.name
script = bundle(payload)
encoded = re.search(r"<<'ANTIGRAVITY_SOURCES'[^\n]*\n(.*?)\nANTIGRAVITY_SOURCES", script, re.S).group(1)
assert base64.b64decode(encoded) == payload
bash = str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe") if os.name == "nt" else shutil.which("bash")
assert bash and Path(bash).is_file(), "Bash is required"
with tempfile.TemporaryDirectory(prefix="ag source bundle ") as temporary:
    root = Path(temporary)
    launcher = root / "unlock_and_restore.sh"
    launcher.write_text(script, encoding="utf-8", newline="\n")
    subprocess.run([bash, "-n", str(launcher)], check=True, timeout=10)
    tools = root / "Rust toolchain" / "bin"
    tools.mkdir(parents=True)
    cargo = tools / "cargo"
    cargo.write_text(r'''#!/bin/bash
set -euo pipefail
[[ "$#" == 9 && "$1" == build && "$2" == --release && "$3" == --locked && "$4" == --bin && "$5" == antigravity-bypass-russia && "$6" == --manifest-path && "$8" == --target-dir ]] || exit 92
[[ -f "$7" && -f "$(dirname -- "$7")/src/system/guarded_io.rs" ]] || exit 93
id -u >> "$ABR_BUILD_LOG"
[[ "$ABR_BUILD_EXIT" == 0 ]] || exit "$ABR_BUILD_EXIT"
mkdir -p -- "$9/release"
cat > "$9/release/antigravity-bypass-russia" <<'ENGINE'
#!/bin/bash
printf '%s\n' "$@"
exit 7
ENGINE
chmod +x "$9/release/antigravity-bypass-russia"
''', encoding="utf-8", newline="\n")
    cargo.chmod(0o755)
    environment = root / "environment.sh"
    environment.write_text(r'''uname() { if [[ "$1" == -s ]]; then echo "$ABR_OS"; else echo "$ABR_ARCH"; fi; }
id() { if [[ "$1" == -u ]]; then echo "$ABR_UID"; else command id "$@"; fi; }
xcode-select() { [[ "$1" == -p && "$ABR_XCODE" == 1 ]]; }
exec() {
  if [[ "$1" != /usr/bin/sudo ]]; then builtin exec "$@"; fi
  shift
  [[ "$1" == -H && "$2" == -u && "$3" == '#501' && "$4" == -- && "$5" == /bin/bash ]] || return 94
  export ABR_UID=501
  unset SUDO_UID
  shift 4
  "$@"
  exit $?
}
''', encoding="utf-8", newline="\n")
    if sys.platform != "darwin":
        with environment.open("a", encoding="utf-8") as out:
            out.write("base64() { command base64 -d; }\nshasum() { command sha256sum; }\n")
    arguments = ["status", "space and кириллица", 'a"b', "", "C:\\Folder with space\\"]

    def env(home, **updates):
        result = dict(os.environ, HOME=home.as_posix(), CARGO_HOME=tools.parent.as_posix(),
                      PATH="", BASH_ENV=environment.as_posix(), MSYS_NO_PATHCONV="1",
                      ABR_OS="Darwin", ABR_ARCH="arm64", ABR_UID="501", ABR_XCODE="1",
                      ABR_BUILD_EXIT="0", ABR_BUILD_LOG=(home / "build.log").as_posix(), SUDO_UID="")
        result.update(updates)
        home.mkdir()
        return result

    def run(environment, path=launcher):
        # Construct the argument boundary inside Bash. Git Bash's additional
        # Windows command-line translation mangles empty/quoted arguments.
        invocation = root / "invoke.sh"
        invocation.write_text("exec /bin/bash " + " ".join(shlex.quote(value) for value in [path.as_posix(), *arguments]) + "\n", encoding="utf-8", newline="\n")
        return subprocess.run([bash, str(invocation)], env=environment, capture_output=True,
                              encoding="utf-8", timeout=30)

    for arch in ["arm64", "x86_64"]:
        home = root / f"home {arch}"
        current = env(home, ABR_ARCH=arch)
        first = run(current)
        assert first.returncode == 7 and first.stdout.splitlines() == arguments, first
        second = run(dict(current, CARGO_HOME=(root / "missing Rust").as_posix(), ABR_XCODE="0"))
        assert second.returncode == 7 and second.stdout.splitlines() == arguments, second
        assert (home / "build.log").read_text().splitlines() == ["501"]
        print(f"PASS: {arch}, exact argument forwarding, user build and verified cache reuse")
        engine = next(path for path in home.rglob("antigravity-bypass-russia")
                      if path.is_file() and path.parent.name == arch)
        engine.write_text("#!/bin/bash\nexit 99\n", encoding="utf-8", newline="\n")
        repaired = run(current)
        assert repaired.returncode == 7 and repaired.stdout.splitlines() == arguments, repaired
        assert (home / "build.log").read_text().splitlines() == ["501", "501"]
        print(f"PASS: {arch}, damaged cache rebuilds from the included sources")

    for case, changes, error in [
        ("non Mac", {"ABR_OS": "Linux"}, "macOS"),
        ("no Xcode", {"ABR_XCODE": "0"}, "xcode-select"),
        ("no Cargo", {"CARGO_HOME": (root / "absent").as_posix()}, "Rust"),
        ("root without user", {"ABR_UID": "0"}, "sudo"),
    ]:
        home = root / case
        result = run(env(home, **changes))
        assert result.returncode == 1 and error in result.stderr and not (home / "build.log").exists(), result
        print(f"PASS: {case} refuses before build")

    home = root / "failed build"
    result = run(env(home, ABR_BUILD_EXIT="31"))
    assert result.returncode == 31 and not list(home.rglob("engine.sha256")), result
    print("PASS: build failure preserves exit status and never publishes an engine")

    home = root / "old sudo invocation"
    result = run(env(home, ABR_UID="0", SUDO_UID="501"))
    assert result.returncode == 7 and (home / "build.log").read_text().strip() == "501", result
    print("PASS: sudo invocation drops privileges before compiling")

    corrupted = root / "corrupt.sh"
    bad = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    corrupted.write_text(script.replace(encoded, bad), encoding="utf-8", newline="\n")
    home = root / "corrupt payload"
    result = run(env(home), corrupted)
    assert result.returncode == 1 and "повреждены" in result.stderr and not (home / "build.log").exists(), result
    print("PASS: payload checksum mismatch refuses before extraction/build")

print("PASS: bundled sources match the current workspace; no installed software was changed")
