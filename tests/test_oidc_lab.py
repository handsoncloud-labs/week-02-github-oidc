import json

import pytest

import oidc

HOST = oidc.OIDC_HOST


def policy(sub_op="StringEquals", sub="repo:me/lab:ref:refs/heads/main", with_sub=True):
    cond = {"StringEquals": {f"{HOST}:aud": "sts.amazonaws.com"}}
    if with_sub:
        cond.setdefault(sub_op, {})[f"{HOST}:sub"] = sub
    return {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                           "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/" + HOST},
                           "Condition": cond}]}


def test_trust_exact_subject_is_not_wildcard():
    t = oidc.analyze_trust(policy())
    assert (t["repo"], t["branch"], t["audience"], t["wildcard"]) == ("me/lab", "main", "sts.amazonaws.com", False)


def test_trust_understands_immutable_subjects():
    t = oidc.analyze_trust(policy(sub="repo:me@11/lab@22:ref:refs/heads/main"))
    assert (t["repo"], t["branch"], t["pins_ids"], t["wildcard"]) == ("me/lab", "main", True, False)
    assert oidc.analyze_trust(policy())["pins_ids"] is False


@pytest.mark.parametrize("p", [
    policy(sub="repo:me/*:ref:refs/heads/main"),
    policy(sub_op="StringLike", sub="repo:me/lab:ref:refs/heads/main"),
    policy(with_sub=False),
])
def test_trust_flags_wide_or_missing_subject(p):
    assert oidc.analyze_trust(p)["wildcard"] is True


def test_trust_requires_web_identity_statement():
    with pytest.raises(ValueError):
        oidc.analyze_trust({"Statement": [{"Action": "sts:AssumeRole"}]})


def test_parse_claims_from_actions_log():
    log = "deploy\tShow OIDC claims\t2026-10-28T10:00:00Z CLAIM sub=repo:me/lab:ref:refs/heads/main\n" \
          "deploy\tShow OIDC claims\t2026-10-28T10:00:00Z CLAIM aud=sts.amazonaws.com\n"
    assert oidc.parse_claims(log) == {"sub": "repo:me/lab:ref:refs/heads/main", "aud": "sts.amazonaws.com"}


def test_redact_hides_account_ids_only():
    assert oidc.redact("s3://hoc-oidc-123456789012-site/x 20 files") == "s3://hoc-oidc-************-site/x 20 files"


def test_configured_minutes_reads_the_workflow():
    assert oidc.configured_minutes() == 15


VIEW = {
    "status": "completed", "conclusion": "success",
    "jobs": [{"startedAt": "2026-10-28T10:00:00Z", "completedAt": "2026-10-28T10:00:21Z",
              "steps": [{"name": "Set up job", "conclusion": "success"},
                        {"name": "Show OIDC claims", "conclusion": "success"},
                        {"name": "Run aws-actions/configure-aws-credentials@v4", "conclusion": "success"},
                        {"name": "Post Run actions/checkout@v4", "conclusion": "success"}]}],
}
LOG_OK = ("CLAIM sub=repo:me/lab:ref:refs/heads/main\n"
          "ASSUMED arn:aws:sts::123456789012:assumed-role/hoc-oidc-deploy/GitHubActions\n"
          "upload: site/index.html to s3://hoc-oidc-123456789012-site/site/index.html\n")


def test_summarize_successful_run():
    r = oidc.summarize(VIEW, LOG_OK)
    assert r["run_seconds"] == 21 and r["role_name"] == "hoc-oidc-deploy" and r["denied"] is False
    assert r["object"].endswith("/site/index.html")
    assert [n for n, _ in r["steps"]] == ["Show OIDC claims", "Run aws-actions/configure-aws-credentials@v4"]


def test_summarize_denied_run():
    view = {**VIEW, "conclusion": "failure"}
    r = oidc.summarize(view, "Error: Could not assume role with OIDC: Not authorized to perform "
                             "sts:AssumeRoleWithWebIdentity\n")
    assert r["denied"] is True and r["role_name"] == "" and r["object"] == ""


def test_trigger_waits_for_a_newer_run():
    ids = iter([100, 100, 101])  # before, first poll (same), second poll (new)
    calls = []

    def fake_gh(*args):
        calls.append(args[:2])
        if args[0] == "run":
            return json.dumps([{"databaseId": next(ids)}])
        return ""

    assert oidc.trigger("me/lab", "main", gh=fake_gh, sleep=lambda s: None) == 101
    assert ("workflow", "run") in calls


def test_ensure_branch_tolerates_existing():
    def fake_gh(*args):
        if "--jq" in args:
            return "abc123\n"
        raise RuntimeError("gh api failed: Reference already exists")

    oidc.ensure_branch("me/lab", "demo-denied", "main", gh=fake_gh)  # no raise


def test_short_sha_only_shortens_full_commit_hashes():
    full = "aws-actions/configure-aws-credentials@e1253824e5c10ff9df46874f81ed3ec929e19cfd"
    assert oidc.short_sha(full) == "aws-actions/configure-aws-credentials@e125382"
    assert oidc.short_sha("actions/checkout@v4") == "actions/checkout@v4"
