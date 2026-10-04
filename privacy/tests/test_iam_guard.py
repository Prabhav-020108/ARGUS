"""IAM guard: offline unit tests plus an opt-in live check against the real scanner identity.

Run the live check once (PowerShell):
    $env:ARGUS_LIVE_IAM_CHECK = "1"
    python -m pytest privacy/tests/test_iam_guard.py -v -rw
"""

import os
import warnings

import pytest

from privacy.iam_guard import (
    find_forbidden_permissions,
    find_watchlist_permissions,
)


def _doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(actions, resource="*"):
    return {"Effect": "Allow", "Action": actions, "Resource": resource}


def test_security_audit_style_policy_is_clean():
    doc = _doc(_allow([
        "iam:Get*", "iam:List*", "s3:GetBucket*", "s3:GetEncryptionConfiguration",
        "s3:GetObjectAcl", "s3:GetObjectTagging", "ec2:Describe*", "kms:Describe*", "kms:Get*",
        "kms:List*", "secretsmanager:DescribeSecret", "secretsmanager:ListSecrets",
        "dynamodb:DescribeTable", "dynamodb:ListTables", "ssm:Describe*", "sqs:GetQueueAttributes",
    ]))
    assert find_forbidden_permissions([doc]) == []


def test_explicit_s3_getobject_is_flagged():
    assert find_forbidden_permissions([_doc(_allow(["s3:GetObject"]))]) == ["s3:GetObject"]


def test_single_string_action_is_flagged():
    assert find_forbidden_permissions([_doc(_allow("secretsmanager:GetSecretValue"))]) == [
        "secretsmanager:GetSecretValue"
    ]


def test_service_wildcard_is_flagged():
    flagged = find_forbidden_permissions([_doc(_allow(["s3:*"]))])
    assert "s3:GetObject" in flagged and "s3:GetObjectVersion" in flagged


def test_get_wildcard_is_flagged():
    assert "s3:GetObject" in find_forbidden_permissions([_doc(_allow(["s3:Get*"]))])


def test_global_wildcard_flags_everything():
    assert len(find_forbidden_permissions([_doc(_allow(["*"]))])) > 10


def test_wildcards_are_case_insensitive():
    assert "s3:GetObject" in find_forbidden_permissions([_doc(_allow(["S3:getobject"]))])


def test_database_and_secret_reads_are_flagged():
    flagged = find_forbidden_permissions(
        [_doc(_allow(["dynamodb:Scan", "rds-data:ExecuteStatement", "ssm:GetParameter", "kms:Decrypt"]))]
    )
    assert flagged == ["dynamodb:Scan", "kms:Decrypt", "rds-data:ExecuteStatement", "ssm:GetParameter"]


def test_deny_statements_are_ignored():
    doc = _doc({"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"})
    assert find_forbidden_permissions([doc]) == []


def test_notaction_allow_flags_everything_not_excluded():
    doc = _doc({"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"})
    assert "s3:GetObject" in find_forbidden_permissions([doc])


def test_notaction_that_excludes_the_data_plane_is_clean():
    doc = _doc({"Effect": "Allow", "NotAction": ["s3:*", "secretsmanager:*", "ssm:*", "kms:*",
                                                 "dynamodb:*", "rds-data:*", "rds-db:*", "athena:*",
                                                 "redshift-data:*", "sqs:*", "kinesis:*"],
                "Resource": "*"})
    assert find_forbidden_permissions([doc]) == []


def test_single_statement_object_is_supported():
    doc = {"Version": "2012-10-17", "Statement": _allow(["s3:GetObject"])}
    assert find_forbidden_permissions([doc]) == ["s3:GetObject"]


def test_one_bad_document_among_many_is_found():
    clean = _doc(_allow(["iam:Get*"]))
    dirty = _doc(_allow(["s3:GetObject"]))
    assert find_forbidden_permissions([clean, dirty, clean]) == ["s3:GetObject"]


def test_watchlist_reports_but_does_not_fail():
    doc = _doc(_allow(["cognito-idp:ListUsers", "rds:DownloadDBLogFilePortion"]))
    assert find_forbidden_permissions([doc]) == []
    assert find_watchlist_permissions([doc]) == ["cognito-idp:ListUsers", "rds:DownloadDBLogFilePortion"]


@pytest.mark.skipif(
    os.environ.get("ARGUS_LIVE_IAM_CHECK") != "1",
    reason="live AWS check; set ARGUS_LIVE_IAM_CHECK=1 to run it",
)
def test_live_scanner_identity_has_no_data_plane_permissions():
    boto3 = pytest.importorskip("boto3")
    from privacy.iam_guard import fetch_identity_policy_documents

    session = boto3.Session(profile_name=os.environ.get("AWS_PROFILE", "argus-scanner"))
    name, docs = fetch_identity_policy_documents(session)
    assert docs, "no policy documents found for identity {}".format(name)
    for action in find_watchlist_permissions(docs):
        warnings.warn("scanner identity grants watchlist action {}".format(action))
    assert find_forbidden_permissions(docs) == []
