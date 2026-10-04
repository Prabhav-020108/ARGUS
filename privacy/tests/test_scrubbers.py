import pytest

from privacy.scrubbers import detect, presidio_available, scrub

SAMPLES = {
    "EMAIL_ADDRESS": "mail meenal.sharma@example-corp.in now",
    "IN_AADHAAR": "id 2345 6789 0123 here",
    "IN_PAN": "pan ABCDE1234F here",
    "IN_MOBILE": "call +91 98765 43210 please",
    "CREDIT_CARD": "card 4111 1111 1111 1111 expiry",
}
SECRETS = {
    "AWS_ACCESS_KEY_ID": "key AKIAIOSFODNN7EXAMPLE end",
    "AWS_SECRET_ACCESS_KEY": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "PRIVATE_KEY_BLOCK": "-----BEGIN RSA PRIVATE KEY-----",
    "JWT": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
    "GITHUB_TOKEN": "ghp_" + "a" * 36,
    "API_KEY_SK": "sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2",
    "GENERIC_SECRET_ASSIGNMENT": "password=Sup3rS3cret!",
}


@pytest.mark.parametrize("entity,text", SAMPLES.items())
def test_regex_engine_detects_personal_data(entity, text):
    assert entity in {h.entity for h in detect(text, engine="regex")}


@pytest.mark.parametrize("entity,text", SECRETS.items())
def test_secret_scanner_detects_secrets(entity, text):
    assert entity in {h.entity for h in detect(text, engine="regex")}


@pytest.mark.parametrize("entity,text", SAMPLES.items())
def test_presidio_engine_detects_personal_data(entity, text):
    if not presidio_available():
        pytest.skip("presidio-analyzer is not installed in this environment")
    assert entity in {h.entity for h in detect(text, engine="presidio")}


def test_presidio_and_regex_engines_agree_on_spans():
    if not presidio_available():
        pytest.skip("presidio-analyzer is not installed in this environment")
    for text in SAMPLES.values():
        a = sorted((h.entity, h.start, h.end) for h in detect(text, engine="presidio") if h.kind == "pii")
        b = sorted((h.entity, h.start, h.end) for h in detect(text, engine="regex") if h.kind == "pii")
        assert a == b


def test_luhn_rejects_random_digits():
    assert not [h for h in detect("order 1234 5678 9012 3456", engine="regex") if h.entity == "CREDIT_CARD"]


def test_lowercase_names_are_not_pan():
    assert detect("bucket argus1234a", engine="regex") == []


def test_tokens_and_public_constants_are_clean():
    for text in ("BUCKET_1", "arn:aws:s3:::BUCKET_1/*", "CIDR_PRIV_2", "0.0.0.0/0", "AWSS3Bucket",
                 "arn:aws:iam::aws:policy/AdministratorAccess", "us-east-1", "[REDACTED_EMAIL_ADDRESS]"):
        assert detect(text) == [], text


def test_scrub_redacts_and_counts_without_keeping_the_value():
    rec = {"note": "contact meenal@example.in or ABCDE1234F", "n": ["password=hunter2", 5, True, None]}
    clean, hits = scrub(rec)
    blob = str(clean)
    assert "meenal@example.in" not in blob and "ABCDE1234F" not in blob and "hunter2" not in blob
    assert "[REDACTED_EMAIL_ADDRESS]" in blob and "[REDACTED_IN_PAN]" in blob
    assert hits["presidio_hits"] == 2 and hits["secret_scan_hits"] == 1
    assert clean["n"][1:] == [5, True, None]


def test_scrub_handles_numbers_that_look_like_ids():
    clean, hits = scrub({"x": 234567890123})
    assert clean["x"] == "[REDACTED_IN_AADHAAR]" and hits["presidio_hits"] == 1


def test_scrub_cleans_dict_keys_too():
    clean, _ = scrub({"AKIAIOSFODNN7EXAMPLE": "v"})
    assert "AKIAIOSFODNN7EXAMPLE" not in str(clean)


def test_scrub_does_not_mutate_input_and_clean_input_is_unchanged():
    rec = {"a": "plain text", "b": ["BUCKET_1", 3]}
    clean, hits = scrub(rec)
    assert clean == rec and hits == {"presidio_hits": 0, "secret_scan_hits": 0}
