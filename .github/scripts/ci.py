"""CI decisions and reports for checks.yml and release.yml (stdlib only).

  ci.py changes        decide whether the Rust jobs must run (GITHUB_OUTPUT rust=true|false)
  ci.py verified-run   find a green checks.yml run that ran the full suite for GITHUB_SHA
  ci.py timing         write each job's time against its budget to the run summary
  ci.py build-tests CARGO_ARGS...   cargo test --no-run; export TEST_BIN and CLI_BIN
  ci.py wait-artifact NAME PRODUCER_JOB   wait for another job's upload in this run
  ci.py docs-only PATH...  print which paths the Rust filter treats as docs-only (for tests)

The Rust filter compares HEAD with the last commit whose Rust jobs passed on this
branch, not with the previous push, so a cancelled or red run can never be hidden
by a later docs-only commit.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Jobs whose success proves the full Rust suite ran for a commit.
RUST_JOB_PREFIXES = ("Rust - ", "Checks - ", "Linux namespaces", "Build - aarch64")
FULL_SUITE_MARKER = "Rust - "

# Paths that no Rust job reads. tests/verify_ci_filter.py fails the build if a
# Rust-job input starts referencing one of them.
DOCS_ONLY_DIRS = ("docs/",)
DOCS_ONLY_EXCEPT = ("docs/releases/",)  # verify_release.py requires the release notes


def docs_only(path):
    if any(path.startswith(prefix) for prefix in DOCS_ONLY_EXCEPT):
        return False
    if any(path.startswith(prefix) for prefix in DOCS_ONLY_DIRS):
        return True
    return "/" not in path and path.endswith(".md")


def api(path, params=None):
    url = f"{os.environ.get('GITHUB_API_URL', 'https://api.github.com')}/{path.lstrip('/')}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "checks-ci",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def output(**values):
    target = os.environ.get("GITHUB_OUTPUT")
    lines = "".join(f"{key}={value}\n" for key, value in values.items())
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(lines)
    print(lines, end="")


def summary(text):
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)


def job_name(job):
    """A job's own name; jobs of a called workflow are listed as "Caller / Job"."""
    return job["name"].split(" / ")[-1]


def run_jobs(repo, run_id):
    jobs, page = [], 1
    while True:
        batch = api(f"repos/{repo}/actions/runs/{run_id}/jobs", {"per_page": 100, "page": page, "filter": "latest"})["jobs"]
        jobs += batch
        if len(batch) < 100:
            return jobs
        page += 1


def ran_full_suite(repo, run):
    if run["conclusion"] != "success":
        return False
    jobs = run_jobs(repo, run["id"])
    rust = [job for job in jobs if job_name(job).startswith(RUST_JOB_PREFIXES)]
    return bool(rust) and any(job_name(job).startswith(FULL_SUITE_MARKER) for job in rust) \
        and all(job["conclusion"] == "success" for job in rust)


def checks_runs(repo, **params):
    return api(f"repos/{repo}/actions/workflows/checks.yml/runs", {"per_page": 30, **params})["workflow_runs"]


def changed_files(repo, base, head):
    comparison = api(f"repos/{repo}/compare/{base}...{head}", {"per_page": 300})
    if comparison["status"] not in ("ahead", "identical"):
        return None, f"{base[:12]} is not an ancestor of {head[:12]} ({comparison['status']})"
    files = comparison.get("files", [])
    if len(files) >= 300:
        return None, "the comparison lists 300 or more files"
    paths = set()
    for item in files:
        paths.add(item["filename"])
        if item.get("previous_filename"):
            paths.add(item["previous_filename"])
    return sorted(paths), None


def changes():
    repo, sha = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"]
    event, ref = os.environ["GITHUB_EVENT_NAME"], os.environ.get("GITHUB_REF", "")
    payload = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
    if os.environ.get("CI_FULL_SUITE") == "true" or event not in ("push", "pull_request") \
            or not ref.startswith(("refs/heads/", "refs/pull/")):
        return decide(True, f"{event} on {ref} always runs the full suite")
    if event == "pull_request":
        base, head = payload["pull_request"]["base"]["sha"], payload["pull_request"]["head"]["sha"]
        origin = f"pull request base {base[:12]}"
        files, problem = changed_files(repo, base, head)
        if files is None:
            return decide(True, problem)
    else:
        # Newest commit on this branch that passed the Rust jobs and is an ancestor of HEAD.
        head, files = sha, None
        branch = ref.removeprefix("refs/heads/")
        candidates = 0
        for run in checks_runs(repo, branch=branch, event="push", status="success"):
            if run["head_sha"] == head or not ran_full_suite(repo, run):
                continue
            files, problem = changed_files(repo, run["head_sha"], head)
            if files is not None:
                base = run["head_sha"]
                break
            print(f"Skipping {run['head_sha'][:12]}: {problem}")
            candidates += 1
            if candidates == 5:
                break
        if files is None:
            return decide(True, f"no ancestor commit on {branch} passed the Rust jobs")
        origin = f"last commit that passed the Rust jobs, {base[:12]}"
    code = [path for path in files if not docs_only(path)]
    if code:
        shown = ", ".join(code[:8]) + (" ..." if len(code) > 8 else "")
        return decide(True, f"{len(code)} non-docs file(s) changed since the {origin}: {shown}")
    return decide(False, f"only docs changed since the {origin}: {', '.join(files) or 'nothing'}")


def decide(rust, reason):
    summary(f"**Rust jobs:** {'run' if rust else 'skipped'} because {reason}.")
    output(rust=str(rust).lower())


def verified_run():
    """Wait for checks.yml on this commit; report a run that passed the full suite."""
    repo, sha = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"]
    deadline = time.monotonic() + int(os.environ.get("CI_WAIT_SECONDS", "1500"))
    while True:
        runs = checks_runs(repo, head_sha=sha)
        for run in runs:
            if run["status"] == "completed" and ran_full_suite(repo, run):
                summary(f"Reusing checks.yml run [{run['id']}]({run['html_url']}) for {sha[:12]}: "
                        "tests, fixture profiles and packaging checks already passed on this commit.")
                return output(verified="true", run_id=run["id"])
        pending = [run for run in runs if run["status"] != "completed" and run["event"] == "push"]
        if not pending or time.monotonic() > deadline:
            summary(f"No checks.yml run passed the full suite on {sha[:12]}; the release runs it.")
            return output(verified="false", run_id="")
        print(f"Waiting for checks.yml run {pending[0]['id']} on {sha[:12]}", flush=True)
        time.sleep(30)


# Budgets in seconds: (queue, setup, running). Prefix match on the job name.
BUDGETS = [
    ("Changes", (30, 15, 15)),
    ("Rust - ", (30, 60, 240)),
    ("Checks - ", (30, 60, 180)),
    ("Linux namespaces", (30, 30, 60)),
    ("Build - aarch64", (30, 60, 150)),
    ("Pinned App", (30, 30, 120)),
    ("Release build - ", (30, 60, 240)),
    ("Package", (30, 30, 60)),
]
SETUP_STEPS = ("Set up job", "Checkout", "Rust cache", "Python", "Linux packages", "Download build",
               "Cross toolchain", "Fixture cache", "Upstream cache")


def stamp(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")) if text else None


def timing():
    repo, run_id = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"]
    run = api(f"repos/{repo}/actions/runs/{run_id}")
    now = datetime.now(timezone.utc)
    rows, last = [], stamp(run["run_started_at"])
    for job in sorted(run_jobs(repo, run_id), key=lambda job: job["created_at"]):
        if job_name(job) == "Timing report" or not job["started_at"]:
            continue
        created, started = stamp(job["created_at"]), stamp(job["started_at"])
        completed = stamp(job["completed_at"]) or now
        last = max(last, completed)
        setup = waiting = running = 0.0
        for step in job.get("steps", []):
            if not step.get("started_at") or not step.get("completed_at") or step["conclusion"] == "skipped":
                continue
            seconds = (stamp(step["completed_at"]) - stamp(step["started_at"])).total_seconds()
            if step["name"].startswith("Post ") or step["name"] == "Complete job":
                continue
            if step["name"].startswith(SETUP_STEPS):
                setup += seconds
            elif step["name"].startswith("Wait for"):
                waiting += seconds
            else:
                running += seconds
        queue = (started - created).total_seconds()
        budget = next((value for prefix, value in BUDGETS if job_name(job).startswith(prefix)), None)

        def cell(value, limit):
            mark = "" if limit is None or value <= limit else " ⚠"
            return f"{value:.0f}s" + (f" / {limit}s" if limit is not None else "") + mark

        rows.append(f"| {job['name']} | {job['conclusion'] or job['status']} | "
                    f"{cell(queue, budget and budget[0])} | {cell(setup, budget and budget[1])} | "
                    f"{waiting:.0f}s | {cell(running, budget and budget[2])} | "
                    f"{(completed - created).total_seconds():.0f}s |")
    wall = (last - stamp(run["created_at"])).total_seconds()
    goal = 300
    summary("### CI time against budget\n")
    summary(f"Push to result: **{wall:.0f}s** (budget {goal}s at the median, 480s at p95){' ⚠' if wall > goal else ''}. "
            "Budgets are reported, never enforced: shared runners are too noisy to fail on time.\n")
    summary("| Job | Result | Queue | Setup | Waiting on build | Running | Total |\n|---|---|---|---|---|---|---|")
    for row in rows:
        summary(row)


def build_tests():
    """Run `cargo test --no-run ARGS`; export the unit-test and CLI executables it built."""
    import subprocess
    command = ["cargo", "test", "--no-run", "--message-format=json-render-diagnostics", *sys.argv[2:]]
    print("+ " + " ".join(command), flush=True)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, encoding="utf-8")
    found = {}
    for line in process.stdout:
        if not line.startswith("{"):
            print(line, end="")
            continue
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact" or "bin" not in message["target"]["kind"]:
            continue
        if message["target"]["name"] == "antigravity-bypass-russia" and message.get("executable"):
            found["TEST_BIN" if message["profile"]["test"] else "CLI_BIN"] = message["executable"]
    if process.wait():
        sys.exit(process.returncode)
    missing = {"TEST_BIN", "CLI_BIN"} - found.keys()
    if missing:
        sys.exit(f"cargo did not report {', '.join(sorted(missing))}")
    target = os.environ.get("GITHUB_ENV")
    for key, value in found.items():
        print(f"{key}={value}")
        if target:
            with open(target, "a", encoding="utf-8") as handle:
                handle.write(f"{key}={value}\n")


def wait_artifact():
    """Wait until a job in this run uploads an artifact; fail at once if that job ends without it."""
    name, producer = sys.argv[2], sys.argv[3]
    repo, run_id = os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_RUN_ID"]
    start, polls = time.monotonic(), 0
    while True:
        artifacts = api(f"repos/{repo}/actions/runs/{run_id}/artifacts", {"name": name})["artifacts"]
        if any(not artifact["expired"] for artifact in artifacts):
            print(f"{name} is available after {time.monotonic() - start:.0f}s of waiting")
            return
        if polls % 3 == 0:
            jobs = [job for job in run_jobs(repo, run_id) if job_name(job) == producer]
            if not jobs:
                sys.exit(f"No job named {producer!r} in this run")
            if jobs[0]["status"] == "completed":
                sys.exit(f"{producer} finished ({jobs[0]['conclusion']}) without uploading {name}; "
                         "its failure is the one to fix")
        polls += 1
        time.sleep(10)


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "docs-only":
        for path in sys.argv[2:]:
            print(f"{'docs-only' if docs_only(path) else 'code'}\t{path}")
        sys.exit()
    commands = {"changes": changes, "verified-run": verified_run, "timing": timing,
                "build-tests": build_tests, "wait-artifact": wait_artifact}
    if command not in commands:
        sys.exit(__doc__)
    try:
        commands[command]()
    except urllib.error.HTTPError as error:
        sys.exit(f"GitHub API error {error.code}: {error.read()[:500]!r}")
