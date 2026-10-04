import json
import sqlite3

import jsonschema
import pytest
from cryptography.fernet import Fernet

from privacy.vault import TokenVault, VaultError, rehydrate, tokenize
from privacy.vault.tokenizer import _Session
from privacy.airlock.projection import REPO_ROOT

PATCH_IR_SCHEMA = REPO_ROOT / "remediate" / "patch_ir" / "schema.json"


def test_bucket_arn_and_bare_name_share_one_token(vault):
    rec = {"resource_type": "AWSS3Bucket", "resource_id": "acme-prod",
           "fields": {"name": "acme-prod", "arn": "arn:aws:s3:::acme-prod"}}
    out, refs = tokenize(rec, vault=vault)
    assert out["fields"]["name"] == "BUCKET_1"
    assert out["fields"]["arn"] == "arn:aws:s3:::BUCKET_1"
    assert out["resource_ref"] == "BUCKET_1" == out["resource_id"]
    assert list(refs) == ["BUCKET_1"]


def test_iam_arn_keeps_structure(vault):
    rec = {"resource_type": "AWSRole", "resource_id": "x",
           "fields": {"trust": "arn:aws:iam::306255359620:role/argus-test-role-a"}}
    out, _ = tokenize(rec, vault=vault)
    assert out["fields"]["trust"].startswith("arn:aws:iam::ACCOUNT_")
    assert ":role/ROLE_" in out["fields"]["trust"]
    assert "306255359620" not in json.dumps(out) and "argus-test-role-a" not in json.dumps(out)


def test_aws_managed_policy_arn_is_a_public_constant(vault):
    rec = {"resource_type": "AWSPolicy", "resource_id": "x",
           "fields": {"p": "arn:aws:iam::aws:policy/AdministratorAccess"}}
    out, _ = tokenize(rec, vault=vault)
    assert out["fields"]["p"] == "arn:aws:iam::aws:policy/AdministratorAccess"


def test_cidr_handling(vault):
    rec = {"resource_type": "AWSIpPermissionInbound", "resource_id": "r",
           "fields": {"a": "0.0.0.0/0", "b": "10.0.0.0/16", "c": "8.8.8.8", "d": "::/0"}}
    out, _ = tokenize(rec, vault=vault)
    assert out["fields"]["a"] == "0.0.0.0/0"
    assert out["fields"]["b"] == "CIDR_PRIV_1"
    assert out["fields"]["c"] == "CIDR_PUB_1"
    assert out["fields"]["d"] == "::/0"


def test_ids_emails_uuids_accounts(vault):
    rec = {"resource_type": "AWSEC2SecurityGroup", "resource_id": "sg-0123456789abcdef0",
           "fields": {"owner": "meenal@example.in", "key": "1234abcd-12ab-34cd-56ef-1234567890ab",
                      "acct": "306255359620", "vpc": "vpc-0abcdef1234567890"}}
    out, _ = tokenize(rec, vault=vault)
    assert out["resource_ref"] == "SG_1"
    blob = json.dumps(out)
    for real in ("meenal@example.in", "1234abcd-12ab-34cd-56ef-1234567890ab", "306255359620",
                 "vpc-0abcdef1234567890", "sg-0123456789abcdef0"):
        assert real not in blob


@pytest.mark.skipif(not PATCH_IR_SCHEMA.exists(), reason="remediate/patch_ir/schema.json not found")
def test_tokens_match_patch_ir_pattern_and_schema(vault):
    rec = {"finding_id": "F-1", "resource_type": "AWSS3Bucket", "resource_id": "acme-prod",
           "fields": {"resource_type": "AWSS3Bucket"}}
    out, _ = tokenize(rec, vault=vault)
    schema = json.loads(PATCH_IR_SCHEMA.read_text(encoding="utf-8"))
    patch = {"finding_id": "F-1", "resource_ref": out["resource_ref"],
             "ops": [{"op": "set_attr", "attr": "versioning_status", "value": "Enabled"}],
             "rationale_ref": "dpdp.rule6_versioning"}
    jsonschema.validate(patch, schema)


def test_round_trip_rehydrate(vault):
    rec = {"resource_type": "AWSS3Bucket", "resource_id": "acme-prod",
           "fields": {"name": "acme-prod", "arn": "arn:aws:s3:::acme-prod/*",
                      "role": "arn:aws:iam::306255359620:role/svc/app-role", "cidr": "10.1.0.0/24"}}
    out, refs = tokenize(rec, vault=vault)
    back = rehydrate(out, refs, vault=vault)
    assert back["fields"] == rec["fields"]
    assert back["resource_id"] == "acme-prod"


def test_rehydrate_a_patch_ir_object(vault):
    rec = {"resource_type": "AWSS3Bucket", "resource_id": "acme-prod",
           "fields": {"arn": "arn:aws:s3:::acme-prod"}}
    out, refs = tokenize(rec, vault=vault)
    patch = {"resource_ref": out["resource_ref"],
             "ops": [{"op": "add_policy_statement", "value": {"Resource": "arn:aws:s3:::BUCKET_1/*"}}]}
    real = rehydrate(patch, refs, vault=vault)
    assert real["resource_ref"] == "acme-prod"
    assert real["ops"][0]["value"]["Resource"] == "arn:aws:s3:::acme-prod/*"


def test_rehydrate_does_not_confuse_token_prefixes(vault):
    sess = _Session()
    for n in range(1, 12):
        sess.token_for("BUCKET", "bucket-number-{}".format(n))
    refs = vault.put_many(sess.items())
    text = "BUCKET_1 and BUCKET_10 and BUCKET_11"
    assert rehydrate(text, refs, vault=vault) == "bucket-number-1 and bucket-number-10 and bucket-number-11"


def test_vault_file_is_encrypted_at_rest(vault):
    rec = {"resource_type": "AWSS3Bucket", "resource_id": "very-secret-bucket-name", "fields": {}}
    tokenize(rec, vault=vault)
    assert b"very-secret-bucket-name" not in vault.db_path.read_bytes()
    con = sqlite3.connect(str(vault.db_path))
    try:
        assert con.execute("SELECT count(*) FROM tokens").fetchone()[0] == 1
    finally:
        con.close()


def test_wrong_key_cannot_read_the_vault(vault):
    _, refs = tokenize({"resource_type": "AWSS3Bucket", "resource_id": "b", "fields": {}}, vault=vault)
    other = TokenVault(db_path=vault.db_path, key=Fernet.generate_key())
    with pytest.raises(VaultError):
        other.get(refs["BUCKET_1"])


def test_unknown_ref_raises(vault):
    with pytest.raises(VaultError):
        vault.get("does-not-exist")


def test_invalid_key_is_rejected(tmp_path):
    with pytest.raises(VaultError):
        TokenVault(db_path=tmp_path / "v.db", key=b"not-a-valid-fernet-key")


def test_key_file_is_created_and_reused(tmp_path):
    kp = tmp_path / "k.key"
    v1 = TokenVault(db_path=tmp_path / "v.db", key_path=kp)
    _, refs = tokenize({"resource_type": "AWSS3Bucket", "resource_id": "b1", "fields": {}}, vault=v1)
    v2 = TokenVault(db_path=tmp_path / "v.db", key_path=kp)
    assert v2.get(refs["BUCKET_1"]) == "b1"


def test_input_record_is_not_mutated(vault):
    rec = {"resource_type": "AWSS3Bucket", "resource_id": "acme", "fields": {"name": "acme"}}
    snapshot = json.loads(json.dumps(rec))
    tokenize(rec, vault=vault)
    assert rec == snapshot
