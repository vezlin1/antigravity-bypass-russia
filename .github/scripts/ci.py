"""CI helpers for checks.yml (stdlib only).

  ci.py build-tests CARGO_ARGS...         cargo test --no-run; export TEST_BIN and CLI_BIN
  ci.py wait-artifact NAME PRODUCER_JOB   wait for another job's upload in this run
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


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
    commands = {"build-tests": build_tests, "wait-artifact": wait_artifact}
    if command not in commands:
        sys.exit(__doc__)
    try:
        commands[command]()
    except urllib.error.HTTPError as error:
        sys.exit(f"GitHub API error {error.code}: {error.read()[:500]!r}")
