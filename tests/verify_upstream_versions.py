"""Detect upstream drift; this checks published versions, not model access."""
import json
from pathlib import Path
import re
import urllib.request

root = Path(__file__).resolve().parents[1]
pinned = json.loads((root / "tests/upstream-versions.json").read_text())
def read(url):
    request = urllib.request.Request(url, headers={"User-Agent": "antigravity-compatibility-check"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8")

page = read(pinned["source"])
for product, fragment in [("app", "antigravity-hub"), ("ide", "antigravity/stable")]:
    versions = set(re.findall(re.escape(fragment) + r"/(\d+\.\d+\.\d+)-", page))
    assert versions == {pinned[product]}, f"{product}: expected {pinned[product]}, published {versions}"
    print(f"PASS: {product} {pinned[product]} is current on the official download page")
for platform, expected in pinned["cli"].items():
    actual = json.loads(read("https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/" + platform + ".json"))
    assert all(actual.get(key) == expected[key] for key in ["version", "url", "sha512"]), f"CLI updated: {platform}; review new binary before updating fixtures"
    print(f"PASS: CLI {platform} {actual['version']}")
