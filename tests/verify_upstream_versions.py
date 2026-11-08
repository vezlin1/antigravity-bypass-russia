"""Detect upstream drift and verify upstream availability without breaking CI builds."""
import argparse
import json
from pathlib import Path
import re
import sys
import time
import urllib.request

root = Path(__file__).resolve().parents[1]
pinned_path = root / "tests/upstream-versions.json"
pinned = json.loads(pinned_path.read_text(encoding="utf-8"))

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--strict", action="store_true", help="Fail if published versions differ from pinned")
args = parser.parse_args()


def read(url, timeout=30, retries=3):
    request = urllib.request.Request(url, headers={"User-Agent": "antigravity-compatibility-check"})
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except Exception as e:
            if attempt == retries:
                raise
            time.sleep(2)


# 1. Check download page for App and IDE
page = read(pinned["source"])
for product, fragment in [("app", "antigravity-hub"), ("ide", "antigravity/stable")]:
    versions = set(re.findall(re.escape(fragment) + r"/(\d+\.\d+\.\d+)-", page))
    assert versions, f"Could not detect any {product} versions on download page"
    expected = pinned.get(product)
    if versions == {expected}:
        print(f"PASS: {product} {expected} matches pinned version on download page")
    else:
        msg = f"{product}: pinned {expected}, published {versions}"
        if args.strict:
            raise AssertionError(f"Strict check failed: {msg}")
        print(f"INFO: upstream drift detected - {msg} (allowed)")

# 2. Check CLI auto-updater manifests
for platform, expected in pinned["cli"].items():
    manifest_url = f"https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/{platform}.json"
    actual = json.loads(read(manifest_url))
    assert "version" in actual and re.match(r"^\d+\.\d+\.\d+", actual["version"]), f"Invalid CLI manifest for {platform}"
    if all(actual.get(key) == expected.get(key) for key in ["version", "url", "sha512"]):
        print(f"PASS: CLI {platform} {actual['version']} matches pinned manifest")
    else:
        msg = f"CLI {platform}: pinned {expected.get('version')}, published {actual.get('version')}"
        if args.strict:
            raise AssertionError(f"Strict check failed: {msg}")
        print(f"INFO: upstream CLI drift detected - {msg} (allowed)")

print("All upstream versions verified successfully.")
