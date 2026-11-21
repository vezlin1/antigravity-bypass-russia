"""Report changes to Google's published versions and CLI checksums."""

import json
import os
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CLI_MANIFESTS = "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/"
CLI_FIELDS = ("version", "url", "sha512")


def read(url):
    request = urllib.request.Request(url, headers={"User-Agent": "antigravity-compatibility-check"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def main():
    pins = json.loads((ROOT / "tests/upstream-versions.json").read_text(encoding="utf-8"))
    current = pins["current"]
    lines = []
    failed = False

    try:
        page = read(pins["source"])
    except (OSError, ValueError) as error:
        lines.append(f"ERROR App/IDE download page: {error}")
        failed = True
    else:
        for product, fragment in (("app", "antigravity-hub"), ("ide", "antigravity/stable")):
            versions = set(re.findall(re.escape(fragment) + r"/(\d+\.\d+\.\d+)-", page))
            pin = current[product]
            expected = pin["version"]
            published = ", ".join(sorted(versions)) or "no versions found"
            matched = versions == {expected} and pin["url"] in page
            result = "PASS" if matched else "CHANGED" if versions else "ERROR"
            artifact = "" if pin["url"] in page else "; pinned Linux x64 download absent"
            lines.append(f"{result} {product.upper()}: pinned {expected}; published {published}{artifact}")
            failed |= not matched

    for platform, expected in current["cli"].items():
        try:
            actual = json.loads(read(f"{CLI_MANIFESTS}{platform}.json"))
            if not isinstance(actual, dict) or not all(isinstance(actual.get(key), str) for key in CLI_FIELDS):
                raise ValueError("missing version, URL or SHA-512")
        except (OSError, ValueError) as error:
            lines.append(f"ERROR CLI {platform}: {error}")
            failed = True
            continue
        changed = [key for key in CLI_FIELDS if actual[key] != expected[key]]
        if changed:
            failed = True
            lines.append(
                f"CHANGED CLI {platform}: pinned {expected['version']}; "
                f"published {actual['version']}; changed {', '.join(changed)}"
            )
        else:
            lines.append(f"PASS CLI {platform}: {actual['version']}")

    report = "\n".join(lines)
    print(report)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as output:
            output.write(f"### Published Antigravity versions\n\n```text\n{report}\n```\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
