#!/usr/bin/env python3
"""Client for the GitHub Actions -> AWS OIDC lab.

  python oidc.py setup                # set the repo variables from terraform outputs (no secrets)
  python oidc.py trust                # show the role's trust policy and check it for wildcards
  python oidc.py run                  # run deploy.yml on the deploy branch: should succeed
  python oidc.py run demo-denied      # run it on any other branch: STS should refuse
  python oidc.py keys                 # prove the repo holds no AWS keys
  python oidc.py cleanup              # delete the demo branch

Needs the `gh` CLI (logged in) and AWS credentials that can read IAM.
Set HOC_FACTS to also write what happened into the episode's facts.json.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
TF_DIR = HERE / "terraform"
WORKFLOW = "deploy.yml"
WORKFLOW_FILE = HERE / ".github" / "workflows" / WORKFLOW
OIDC_HOST = "token.actions.githubusercontent.com"
DEMO_BRANCH = "demo-denied"
WIDTH = max(40, min(76, shutil.get_terminal_size((80, 24)).columns - 1))

GREEN, RED, CYAN, DIM, BOLD, RESET = (
    ("\033[32m", "\033[31m", "\033[36m", "\033[2m", "\033[1m", "\033[0m")
    if sys.stdout.isatty() or os.environ.get("FORCE_COLOR")
    else ("",) * 6
)

SUB_RE = re.compile(r"^repo:(?P<owner>[^/@:]+)(?:@(?P<owner_id>\d+))?/(?P<name>[^/@:]+)(?:@(?P<repo_id>\d+))?"
                    r":ref:refs/heads/(?P<branch>.+)$")
CLAIM_RE = re.compile(r"CLAIM (\w+)=(\S+)")
ASSUMED_RE = re.compile(r"ASSUMED arn:aws:sts::\d+:assumed-role/([\w+=,.@-]+)/")
DENIED_RE = re.compile(r"Not authorized to perform sts:AssumeRoleWithWebIdentity")
UPLOAD_RE = re.compile(r"upload: \S+ to (s3://\S+)")
HIDDEN_STEPS = ("Set up job", "Complete job", "Post ")


def fail(msg: str) -> "None":
    print(f"{RED}{msg}{RESET}", file=sys.stderr)
    raise SystemExit(1)


def short_sha(name: str) -> str:
    """actions/checkout@3d3c42e5...(40 hex) -> actions/checkout@3d3c42e, as GitHub shows it."""
    return re.sub(r"@([0-9a-f]{7})[0-9a-f]{33}\b", r"@\1", name)


def redact(text: str) -> str:
    """Hide 12-digit AWS account IDs before anything is shown on camera."""
    return re.sub(r"(?<!\d)\d{12}(?!\d)", "************", text)


def record(namespace: str, data: dict) -> None:
    """If HOC_FACTS is set, merge real run output into that JSON file.

    The video narration is filled from this file, so it can only say
    what actually happened on camera.
    """
    path = os.environ.get("HOC_FACTS")
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    facts = json.loads(p.read_text()) if p.exists() else {}
    facts[namespace] = data
    p.write_text(json.dumps(facts, indent=2) + "\n")


# ---------------------------------------------------------------- shell

def sh(*cmd: str, run=subprocess.run) -> str:
    out = run(list(cmd), capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed: {(out.stderr or out.stdout).strip()}")
    return out.stdout


def gh(*args: str) -> str:
    return sh("gh", *args)


def tf_outputs() -> dict:
    raw = json.loads(sh("terraform", f"-chdir={TF_DIR}", "output", "-json"))
    if not raw:
        fail("No Terraform outputs. Run `make EP=week-02-github-oidc lab-up` first.")
    return {k: v["value"] for k, v in raw.items()}


# ---------------------------------------------------------------- analysis

def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def analyze_trust(policy: dict, host: str = OIDC_HOST) -> dict:
    """Pull the audience and subject conditions out of a role's trust policy.

    `wildcard` is True when the subject condition is missing, uses a pattern
    operator, or contains * or ?: any of those widens who can assume the role.
    """
    stmts = [s for s in _as_list(policy["Statement"])
             if "sts:AssumeRoleWithWebIdentity" in _as_list(s.get("Action", []))]
    if not stmts:
        raise ValueError("trust policy has no sts:AssumeRoleWithWebIdentity statement")
    cond = stmts[0].get("Condition", {})

    def find(claim: str) -> tuple[str | None, list[str]]:
        for op, kv in cond.items():
            if f"{host}:{claim}" in kv:
                return op, _as_list(kv[f"{host}:{claim}"])
        return None, []

    _, aud = find("aud")
    sub_op, sub = find("sub")
    wildcard = (
        not sub
        or sub_op != "StringEquals"
        or any(c in v for v in sub for c in "*?")
    )
    m = SUB_RE.match(sub[0]) if len(sub) == 1 else None
    return {
        "audience": aud[0] if aud else "",
        "sub": sub[0] if len(sub) == 1 else ", ".join(sub),
        "sub_operator": sub_op or "(missing)",
        "repo": f"{m['owner']}/{m['name']}" if m else "",
        "branch": m["branch"] if m else "",
        "pins_ids": bool(m and m["owner_id"] and m["repo_id"]),
        "wildcard": wildcard,
    }


def parse_claims(log: str) -> dict:
    return dict(CLAIM_RE.findall(log))


def configured_minutes(workflow: Path = WORKFLOW_FILE) -> int:
    """The credential lifetime the workflow asks the action to request."""
    import yaml

    doc = yaml.safe_load(workflow.read_text())
    for job in doc["jobs"].values():
        for step in job["steps"]:
            if str(step.get("uses", "")).startswith("aws-actions/configure-aws-credentials"):
                return int(step["with"].get("role-duration-seconds", 3600)) // 60
    raise ValueError("no configure-aws-credentials step in the workflow")


# ---------------------------------------------------------------- workflow runs

def _iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def latest_run_id(repo: str, ref: str, gh=gh) -> int:
    runs = json.loads(gh("run", "list", "--repo", repo, "--workflow", WORKFLOW,
                         "--branch", ref, "--limit", "1", "--json", "databaseId") or "[]")
    return runs[0]["databaseId"] if runs else 0


def ensure_branch(repo: str, branch: str, base: str, gh=gh) -> None:
    sha = gh("api", f"repos/{repo}/git/ref/heads/{base}", "--jq", ".object.sha").strip()
    try:
        gh("api", f"repos/{repo}/git/refs", "-f", f"ref=refs/heads/{branch}", "-f", f"sha={sha}")
    except RuntimeError as e:
        if "already exists" not in str(e):
            raise


def trigger(repo: str, ref: str, gh=gh, sleep=time.sleep, timeout: int = 90) -> int:
    before = latest_run_id(repo, ref, gh)
    gh("workflow", "run", WORKFLOW, "--repo", repo, "--ref", ref)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sleep(3)
        rid = latest_run_id(repo, ref, gh)
        if rid > before:
            return rid
    raise TimeoutError(f"no new {WORKFLOW} run appeared on {ref} within {timeout}s")


def wait_for(repo: str, run_id: int, gh=gh, sleep=time.sleep, timeout: int = 300) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        view = json.loads(gh("run", "view", str(run_id), "--repo", repo,
                             "--json", "status,conclusion,jobs"))
        if view["status"] == "completed":
            return view
        sleep(4)
    raise TimeoutError(f"run {run_id} did not finish within {timeout}s")


def summarize(view: dict, log: str) -> dict:
    """Everything the narration may quote, taken from the finished run."""
    job = view["jobs"][0]
    seconds = round((_iso(job["completedAt"]) - _iso(job["startedAt"])).total_seconds())
    assumed = ASSUMED_RE.search(log)
    upload = UPLOAD_RE.search(log)
    return {
        "conclusion": view["conclusion"],
        "claims": parse_claims(log),
        "run_seconds": seconds,
        "role_name": assumed.group(1) if assumed else "",
        "object": upload.group(1) if upload else "",
        "denied": bool(DENIED_RE.search(log)),
        "steps": [(s["name"], s["conclusion"]) for s in job["steps"]
                  if not s["name"].startswith(HIDDEN_STEPS)],
    }


# ---------------------------------------------------------------- commands

def cmd_setup(_args) -> int:
    out = tf_outputs()
    repo = out["github_repo"]
    for name, value in (("AWS_ROLE_ARN", out["role_arn"]), ("ARTIFACT_BUCKET", out["bucket"]),
                        ("AWS_REGION", out["aws_region"])):
        gh("variable", "set", name, "--repo", repo, "--body", value)
        print(f"{GREEN}✓{RESET} variable {name}")
    print(f"{DIM}Variables, not secrets: these are identifiers, useless without a token.{RESET}")
    return 0


def cmd_trust(_args) -> int:
    import boto3

    out = tf_outputs()
    policy = boto3.client("iam").get_role(RoleName=out["role_name"])["Role"]["AssumeRolePolicyDocument"]
    t = analyze_trust(policy)

    print(f"{BOLD}{out['role_name']}{RESET}  trusts  sts:AssumeRoleWithWebIdentity")
    print(f"  {CYAN}aud{RESET} (StringEquals)\n    {t['audience']}")
    print(f"  {CYAN}sub{RESET} ({t['sub_operator']})")
    for line in textwrap.wrap(t["sub"], WIDTH - 4):
        print(f"    {line}")
    if t["wildcard"]:
        print(f"{RED}✗ wildcard or missing condition on sub: too broad{RESET}")
        return 1
    print(f"{GREEN}✓ exact subject, no wildcard{RESET}")
    print(f"{GREEN}✓{RESET} pinned to numeric IDs" if t["pins_ids"] else f"{DIM}– not pinned to numeric IDs{RESET}")
    record("trust", {k: t[k] for k in ("repo", "branch", "audience", "wildcard", "pins_ids")})
    return 0


def cmd_run(args) -> int:
    out = tf_outputs()
    repo, deploy_branch = out["github_repo"], out["deploy_branch"]
    ref = args.ref or deploy_branch
    expect_ok = ref == deploy_branch

    if not expect_ok:
        ensure_branch(repo, ref, deploy_branch)
    print(f"{BOLD}▶ {WORKFLOW}{RESET} on {CYAN}{ref}{RESET}")
    run_id = trigger(repo, ref)
    print(f"{DIM}  run {run_id}, waiting...{RESET}")
    view = wait_for(repo, run_id)
    log = gh("run", "view", str(run_id), "--repo", repo, "--log")
    r = summarize(view, log)

    for name, conclusion in r["steps"]:
        mark = {"success": f"{GREEN}✓", "failure": f"{RED}✗"}.get(conclusion, f"{DIM}–")
        print(f"  {mark}{RESET} {short_sha(name.removeprefix('Run '))}")
    for k in ("sub", "ref"):
        if k in r["claims"]:
            print(f"  {DIM}claim {k}{RESET} {r['claims'][k]}")
    if r["role_name"]:
        print(f"  {DIM}assumed{RESET} {r['role_name']}")
    if r["object"]:
        print(f"  {DIM}uploaded{RESET} {redact(r['object'])}")
    if r["denied"]:
        print(f"  {RED}Not authorized to perform sts:AssumeRoleWithWebIdentity{RESET}")
    print(f"{BOLD}{'success' if r['conclusion'] == 'success' else r['conclusion']}{RESET}"
          f" {DIM}in {r['run_seconds']}s{RESET}")

    if expect_ok:
        if r["conclusion"] != "success" or not r["role_name"] or not r["object"]:
            fail("Expected the deploy branch to succeed. Facts not recorded.")
        record("deploy", {"ref": ref, "conclusion": r["conclusion"], "sub": r["claims"].get("sub", ""),
                          "role_name": r["role_name"], "run_seconds": r["run_seconds"],
                          "object": redact(r["object"])})
        record("creds", {"minutes": configured_minutes()})
    else:
        if r["conclusion"] != "failure" or not r["denied"]:
            fail(f"Expected STS to refuse {ref}. Facts not recorded.")
        record("denied", {"branch": ref, "conclusion": r["conclusion"],
                          "sub": r["claims"].get("sub", ""), "message": "Not authorized"})
    return 0


def cmd_keys(_args) -> int:
    repo = tf_outputs()["github_repo"]
    secrets = [s["name"] for s in json.loads(gh("secret", "list", "--repo", repo, "--json", "name"))]
    variables = [v["name"] for v in json.loads(gh("variable", "list", "--repo", repo, "--json", "name"))]
    aws_secrets = [s for s in secrets if s.upper().startswith("AWS_")]

    print(f"{BOLD}{repo}{RESET}")
    print(f"  secrets    {len(secrets)}  {DIM}{', '.join(secrets) or '(none)'}{RESET}")
    print(f"  variables  {len(variables)}  {DIM}{', '.join(variables) or '(none)'}{RESET}")
    if aws_secrets:
        print(f"{RED}✗ AWS secrets present: {', '.join(aws_secrets)}{RESET}")
        return 1
    print(f"{GREEN}✓ no AWS keys stored in this repo{RESET}")
    record("keys", {"repo_secrets": len(secrets), "repo_variables": len(variables)})
    return 0


def cmd_cleanup(_args) -> int:
    repo = tf_outputs()["github_repo"]
    try:
        gh("api", "-X", "DELETE", f"repos/{repo}/git/refs/heads/{DEMO_BRANCH}")
        print(f"{GREEN}✓{RESET} deleted branch {DEMO_BRANCH}")
    except RuntimeError as e:
        print(f"{DIM}nothing to delete: {e}{RESET}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup").set_defaults(fn=cmd_setup)
    sub.add_parser("trust").set_defaults(fn=cmd_trust)
    p = sub.add_parser("run")
    p.add_argument("ref", nargs="?", help="branch to run on (default: the deploy branch)")
    p.set_defaults(fn=cmd_run)
    sub.add_parser("keys").set_defaults(fn=cmd_keys)
    sub.add_parser("cleanup").set_defaults(fn=cmd_cleanup)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except (RuntimeError, TimeoutError) as e:
        fail(str(e))


if __name__ == "__main__":
    sys.exit(main())
