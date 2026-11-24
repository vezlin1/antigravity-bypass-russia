"""The CI docs filter may skip the Rust jobs only for files that no Rust job reads.

.github/scripts/ci.py treats docs/** (except docs/releases/**) and root *.md files
as docs-only. This check fails when any other tracked file names one of them, so a
test, build script or harness that starts reading a doc also turns the filter off
for it. It runs in the Python job, which the filter never skips.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github" / "scripts"))
from ci import docs_only  # noqa: E402

# Files that may name docs because nothing they do runs in a skippable job.
ALLOWED_READERS = {
    ".github/scripts/ci.py": "defines the filter",
    "tests/verify_ci_filter.py": "this check",
    ".gitignore": "git metadata, not read by builds or tests",
    "Cargo.toml": "`readme` is metadata for `cargo publish`; builds and tests never read it",
    "scripts/bundle_macos_sources.py": "packages README.md; verified by the always-run Python job",
    "scripts/package_macos_build_kit.py": "packages README.md; verified by the always-run Python job",
    "tests/verify_macos_source_bundle.py": "always-run Python job",
}
COMMENT = re.compile(r"^\s*(//|#|<!--|\*|rem\b)", re.IGNORECASE)


def tracked():
    output = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout
    return [name for name in output.decode("utf-8").split("\0") if name]


def main():
    files = tracked()
    docs = sorted(path for path in files if docs_only(path))
    assert docs, "the docs filter matches no tracked file; ci.py and this check disagree"
    names = {path: re.compile(r"(?<![\w.-])" + re.escape(Path(path).name) + r"(?![\w.-])") for path in docs}
    directory = re.compile(r"""["'/\\]docs(?![\w-])""")
    releases = re.compile(r"""docs["']?\s*[/\\,]\s*["']?releases""")
    problems = []
    for path in files:
        if docs_only(path) or path in ALLOWED_READERS:
            continue
        try:
            text = (ROOT / path).read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if COMMENT.match(line):
                continue
            hits = [doc for doc, pattern in names.items() if pattern.search(line)]
            if directory.search(line) and not releases.search(line):
                hits.append("docs/")
            for doc in hits:
                problems.append(f"{path}:{number} names {doc}: {line.strip()[:120]}")
    if problems:
        print("These files name paths the CI docs filter skips. Either stop reading the doc, or "
              "narrow docs_only() in .github/scripts/ci.py:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(f"PASS: {len(docs)} docs-only files are not named by any Rust-job input")
    check_decisions()


def run(number, sha, rust="success"):
    jobs = [{"name": "Rust - x86_64-unknown-linux-gnu", "conclusion": rust},
            {"name": "Checks - x86_64-unknown-linux-gnu", "conclusion": "success"}]
    return {"id": number, "head_sha": sha, "conclusion": "success", "jobs": jobs}


def decide(runs, comparisons, event="push", files_for_pr=None):
    """Run ci.changes() against a fake GitHub API; return the rust output."""
    import importlib, json, os, tempfile
    ci = importlib.import_module("ci")

    def api(path, params=None):
        if path.endswith("/actions/workflows/checks.yml/runs"):
            return {"workflow_runs": [dict(item, status="completed") for item in runs]}
        if "/jobs" in path:
            return {"jobs": next(item["jobs"] for item in runs if f"/runs/{item['id']}/" in path)}
        base = path.split("/compare/")[1].split("...")[0]
        status, files = comparisons.get(base, ("diverged", []))
        return {"status": status, "files": [dict(filename=name) if isinstance(name, str) else name for name in files]}

    with tempfile.TemporaryDirectory() as folder:
        event_path, output_path = Path(folder, "event.json"), Path(folder, "output")
        payload = {"pull_request": {"base": {"sha": "base"}, "head": {"sha": "head"}}} if event == "pull_request" else {}
        event_path.write_text(json.dumps(payload))
        saved = dict(os.environ)
        os.environ.update(GITHUB_REPOSITORY="o/r", GITHUB_SHA="head", GITHUB_EVENT_NAME=event,
                          GITHUB_REF="refs/pull/1/merge" if event == "pull_request" else "refs/heads/main",
                          GITHUB_EVENT_PATH=str(event_path), GITHUB_OUTPUT=str(output_path))
        os.environ.pop("GITHUB_STEP_SUMMARY", None)
        os.environ.pop("CI_FULL_SUITE", None)
        original, ci.api = ci.api, api
        try:
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()):
                ci.changes()
        finally:
            ci.api = original
            os.environ.clear()
            os.environ.update(saved)
        return output_path.read_text().strip()


def check_decisions():
    """Changes that must never be hidden behind the docs filter, as fake run histories."""
    docs, code = ["README.md", "docs/linux-compatibility.md"], ["README.md", "src/net/rank.rs"]
    cases = [
        ("docs-only push after a verified commit", "false", [run(1, "a")], {"a": ("ahead", docs)}),
        # The push that cancelled a code commit's run is diffed against the last verified
        # commit, so the cancelled commit's code is in the diff (public repo, 2b8fbd5 -> 049c08c).
        ("docs push that cancelled a code push", "true", [run(1, "a")], {"a": ("ahead", code)}),
        ("a docs-only run is not a verified base", "true", [run(2, "d", rust="skipped"), run(1, "a")],
         {"d": ("ahead", docs), "a": ("ahead", code)}),
        ("source moved under docs/", "true", [run(1, "a")],
         {"a": ("ahead", [{"filename": "docs/rank.rs", "previous_filename": "src/net/rank.rs"}])}),
        ("release notes are read by verify_release.py", "true", [run(1, "a")],
         {"a": ("ahead", ["docs/releases/v2.6.0.md"])}),
        ("verified commit is not an ancestor", "true", [run(1, "a")], {"a": ("diverged", docs)}),
        ("no verified commit at all", "true", [], {}),
        ("too many files to list", "true", [run(1, "a")], {"a": ("ahead", [f"docs/{n}.md" for n in range(300)])}),
        ("skip a diverged run, use an older ancestor", "false", [run(2, "x"), run(1, "a")],
         {"x": ("diverged", []), "a": ("ahead", docs)}),
    ]
    failures = []
    for label, expected, runs, comparisons in cases:
        actual = decide(runs, comparisons).removeprefix("rust=")
        if actual != expected:
            failures.append(f"{label}: Rust jobs {'run' if actual == 'true' else 'skipped'}, expected the opposite")
    pr_docs = decide([], {"base": ("ahead", docs)}, event="pull_request").removeprefix("rust=")
    pr_code = decide([], {"base": ("ahead", code)}, event="pull_request").removeprefix("rust=")
    if (pr_docs, pr_code) != ("false", "true"):
        failures.append(f"pull request: docs-only -> {pr_docs}, code -> {pr_code}")
    if failures:
        sys.exit("CI docs filter would hide changes:\n" + "\n".join(failures))
    print(f"PASS: {len(cases) + 2} filter decisions, including a docs push that cancelled a code push")


if __name__ == "__main__":
    main()
