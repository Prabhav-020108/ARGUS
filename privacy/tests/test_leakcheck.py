import base64

import pytest

from privacy.airlock.leakcheck import LeakDetected, leak_check


def test_clean_payload_passes():
    payload = {"finding_id": "F-1", "resource_id": "BUCKET_1",
               "fields": {"resource_type": "AWSS3Bucket", "default_encryption": False, "ports": [22, 443]}}
    assert leak_check(payload, ["acme-prod"]) == {"vault_hits": 0, "secret_hits": 0, "pii_hits": 0}


def test_real_vault_value_in_payload_is_blocked():
    with pytest.raises(LeakDetected) as exc:
        leak_check({"fields": {"name": "Acme-Prod"}}, ["acme-prod"])
    assert exc.value.summary["vault_hits"] == 1
    assert "acme-prod" not in str(exc.value).lower()  # message must never contain the value


def test_vault_value_inside_an_arn_is_blocked():
    with pytest.raises(LeakDetected):
        leak_check({"arn": "arn:aws:s3:::acme-prod/*"}, ["acme-prod"])


def test_vault_value_must_match_as_a_whole_word():
    assert leak_check({"x": "metadata_bucket1"}, ["data"])["vault_hits"] == 0


def test_vault_value_split_across_fields_is_blocked():
    with pytest.raises(LeakDetected):
        leak_check({"a": "acme-customer", "b": "-pii-prod"}, ["acme-customer-pii-prod"])


def test_secret_in_dict_key_is_blocked():
    with pytest.raises(LeakDetected):
        leak_check({"AKIAIOSFODNN7EXAMPLE": "x"})


def test_base64_encoded_secret_is_blocked():
    encoded = base64.b64encode(b"AKIAIOSFODNN7EXAMPLE").decode()
    with pytest.raises(LeakDetected) as exc:
        leak_check({"note": encoded})
    assert exc.value.summary["secret_hits"] >= 1


def test_urlsafe_base64_encoded_secret_is_blocked():
    encoded = base64.urlsafe_b64encode(b"password=Sup3rS3cret!!").decode()
    with pytest.raises(LeakDetected):
        leak_check({"note": encoded})


def test_base64_encoded_vault_value_is_blocked():
    encoded = base64.b64encode(b"acme-customer-pii-prod").decode()
    with pytest.raises(LeakDetected):
        leak_check({"note": encoded}, ["acme-customer-pii-prod"])


def test_secret_split_across_list_items_is_blocked():
    with pytest.raises(LeakDetected):
        leak_check({"note": ["AKIAIOSF", "ODNN7EXAMPLE"]})


def test_personal_data_is_blocked():
    with pytest.raises(LeakDetected) as exc:
        leak_check({"note": "mail meenal@example.in"})
    assert exc.value.summary["pii_hits"] >= 1


def test_numeric_personal_data_is_blocked():
    with pytest.raises(LeakDetected):
        leak_check({"x": 234567890123})


def test_ordinary_base64_looking_field_names_do_not_false_positive():
    payload = {"fields": {"server_side_encryption_enabled": True, "block_public_acls": False,
                          "restrict_public_buckets": True, "encryption_algorithm": "aws:kms"}}
    assert leak_check(payload, ["acme-prod"])["secret_hits"] == 0
