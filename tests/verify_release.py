"""Read-only smoke checks against the actual release binary."""
import os
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import tempfile

root = Path(__file__).resolve().parents[1]
version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
if os.environ.get("GITHUB_REF_TYPE") == "tag":
    assert os.environ["GITHUB_REF_NAME"] == f"v{version}", "Tag and package version differ"
binary = Path(sys.argv[1]).resolve()


def run(*args):
    return subprocess.run([str(binary), *args], capture_output=True, encoding="utf-8", timeout=30)


result = run("--version")
assert result.returncode == 0 and result.stdout.strip() == f"antigravity-bypass-russia v{version}", result
result = run("--help")
assert result.returncode == 0 and all(word in result.stdout for word in ["unlock", "rollback", "diagnostics", "report"]), result
for args in [("invalid-command",), ("status", "extra"), ("report", ".", "extra")]:
    result = run(*args)
    assert result.returncode == 2, result
result = run("status")
assert result.returncode == 0, result
plain = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
rows = [line for line in plain.splitlines() if line]
assert len(rows) == 9 and all(len(line) == 69 for line in rows), plain
assert all(label in plain for label in ["Обход:", "Antigravity:", "Antigravity IDE:", "Antigravity CLI:", "Модель (журнал):"]), plain
print(f"PASS: release {version}, help, argument errors, status and frame alignment")

# Saving evidence must work even on a runner with no installation, service or working Internet.
# The destination is temporary; report only reads installed state and sends unauthenticated probes.
with tempfile.TemporaryDirectory(prefix="ag diagnostics ") as temporary:
    destination = Path(temporary)
    result = subprocess.run([str(binary), "report", str(destination)], capture_output=True,
                            encoding="utf-8", timeout=60)
    assert result.returncode == 0, result
    reports = list(destination.glob("antigravity-diagnostics-*.json"))
    assert len(reports) == 1, reports
    output_lines = result.stdout.splitlines()
    saved_line = next(i for i, line in enumerate(output_lines) if line.strip() == "Диагностика сохранена:")
    displayed_path = output_lines[saved_line + 1].strip()
    assert not displayed_path.startswith("\\\\?\\"), displayed_path
    assert Path(displayed_path).samefile(reports[0]), displayed_path
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    assert report["schema_version"] == 1 and report["bypass_version"] == version, report
    assert report["model_access"].startswith("not_tested"), report
    assert all(section in report["checks"] for section in ["installations", "service", "configuration", "system_network", "model_observation", "dns_capabilities"]), report
    assert report["checks"]["model_observation"]["completion_confirmed"] is False, report
    assert str(destination) not in reports[0].read_text(encoding="utf-8")
    result = run("report", str(destination / "missing"))
    assert result.returncode == 1 and not (destination / "missing").exists(), result
print("PASS: local diagnostic export, partial results, private destination and save failure exit code")
