"""
ARGUS Phase 4 - control-plane-only IAM guard (step zero of the privacy airlock).

Checks that the identity ARGUS scans with can NOT read data-plane content: no s3:GetObject,
no database query rights, no secret reads. The pure function `find_granted_actions` is
unit-tested offline; `fetch_identity_policy_documents` + `main` check the real scanner.

Run the live check from the repo root (PowerShell):
    python -m privacy.iam_guard
Exit code 0 = clean, 1 = forbidden permissions found, 2 = could not run the check.
"""

import fnmatch
import os
import sys

# Fail the check if any of these is granted (directly or through a wildcard such as s3:* or *).
FORBIDDEN_ACTIONS = (
    "s3:GetObject",
    "s3:GetObjectVersion",
    "secretsmanager:GetSecretValue",
    "secretsmanager:BatchGetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "kms:Decrypt",
    "dynamodb:GetItem",
    "dynamodb:BatchGetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "rds-data:ExecuteStatement",
    "rds-data:BatchExecuteStatement",
    "rds-db:connect",
    "athena:StartQueryExecution",
    "redshift-data:ExecuteStatement",
    "sqs:ReceiveMessage",
    "kinesis:GetRecords",
)

# Not a failure, but worth knowing: these are in AWS's SecurityAudit policy and can expose
# content or personal data. They are reported as warnings so the team can state this
# honestly as a limitation.
WATCHLIST_ACTIONS = (
    "rds:DownloadDBLogFilePortion",
    "cognito-idp:ListUsers",
    "cognito-idp:ListUsersInGroup",
    "identitystore:ListUsers",
    "s3:ListBucket",
)


def _as_list(value):
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _matches(action, patterns):
    a = action.lower()
    return any(fnmatch.fnmatchcase(a, str(p).lower()) for p in patterns)


def find_granted_actions(policy_documents, actions):
    """Which of `actions` do the Allow statements in `policy_documents` grant?

    Deny statements are ignored on purpose (we want the literal absence of the permission).
    Conditions and resource scoping are ignored too (conservative).
    """
    granted = set()
    for doc in policy_documents:
        for stmt in _as_list(doc.get("Statement")):
            if stmt.get("Effect") != "Allow":
                continue
            allow_patterns = _as_list(stmt.get("Action"))
            not_patterns = _as_list(stmt.get("NotAction"))
            for action in actions:
                if allow_patterns and _matches(action, allow_patterns):
                    granted.add(action)
                elif not_patterns and not _matches(action, not_patterns):
                    granted.add(action)
    return sorted(granted)


def find_forbidden_permissions(policy_documents):
    return find_granted_actions(policy_documents, FORBIDDEN_ACTIONS)


def find_watchlist_permissions(policy_documents):
    return find_granted_actions(policy_documents, WATCHLIST_ACTIONS)


# ---------------------------------------------------------------------------
# Live AWS access (read-only IAM calls)
# ---------------------------------------------------------------------------

def _managed_policy_document(iam, policy_arn):
    version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    return iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)["PolicyVersion"]["Document"]


def _paged(iam, operation, key, **kwargs):
    for page in iam.get_paginator(operation).paginate(**kwargs):
        for item in page[key]:
            yield item


def fetch_identity_policy_documents(session):
    """Return (identity_name, [policy documents]) for the caller of `session`.

    Supports an IAM user (plus its groups) or an assumed role.
    """
    sts = session.client("sts")
    iam = session.client("iam")
    arn = sts.get_caller_identity()["Arn"]
    docs = []

    if ":user/" in arn:
        name = arn.split(":user/", 1)[1].split("/")[-1]
        for p in _paged(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name):
            docs.append(_managed_policy_document(iam, p["PolicyArn"]))
        for pname in _paged(iam, "list_user_policies", "PolicyNames", UserName=name):
            docs.append(iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"])
        for g in _paged(iam, "list_groups_for_user", "Groups", UserName=name):
            gname = g["GroupName"]
            for p in _paged(iam, "list_attached_group_policies", "AttachedPolicies", GroupName=gname):
                docs.append(_managed_policy_document(iam, p["PolicyArn"]))
            for pname in _paged(iam, "list_group_policies", "PolicyNames", GroupName=gname):
                docs.append(iam.get_group_policy(GroupName=gname, PolicyName=pname)["PolicyDocument"])
        return name, docs

    if ":assumed-role/" in arn:
        name = arn.split(":assumed-role/", 1)[1].split("/")[0]
        for p in _paged(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name):
            docs.append(_managed_policy_document(iam, p["PolicyArn"]))
        for pname in _paged(iam, "list_role_policies", "PolicyNames", RoleName=name):
            docs.append(iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"])
        return name, docs

    raise RuntimeError("Unsupported identity type (expected an IAM user or an assumed role)")


def main():
    try:
        import boto3

        profile = os.environ.get("AWS_PROFILE", "argus-scanner")
        session = boto3.Session(profile_name=profile)
        name, docs = fetch_identity_policy_documents(session)
    except Exception as exc:  # no credentials, no network, access denied ...
        print("IAM guard could not run: {}: {}".format(type(exc).__name__, exc))
        return 2

    forbidden = find_forbidden_permissions(docs)
    watch = find_watchlist_permissions(docs)
    print("Identity checked        : {}".format(name))
    print("Policy documents checked: {}".format(len(docs)))
    print("Forbidden permissions   : {}".format(forbidden if forbidden else "none"))
    print("Watchlist (warn only)   : {}".format(watch if watch else "none"))
    if forbidden:
        print("FAIL: the scanner identity can read data-plane content.")
        return 1
    print("PASS: the scanner identity has no forbidden data-plane permissions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
