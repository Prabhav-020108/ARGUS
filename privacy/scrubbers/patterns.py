"""
Detector specifications shared by the scrubber and the leak-check.

One place defines what counts as "a secret" and what counts as "personal data",
so the scrubber (which redacts) and the leak-check (which blocks) can never
drift apart.
"""

import re


def luhn_valid(text):
    """Credit-card checksum. True when the digits in `text` pass the Luhn test."""
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# (entity name, regex string, validator or None, score)
# Regex strings are shared with Presidio's PatternRecognizer, so keep them
# case-sensitive-safe (we pass re.MULTILINE only).
PII_SPECS = [
    (
        "EMAIL_ADDRESS",
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b",
        None,
        0.9,
    ),
    # Aadhaar: 12 digits, first digit 2-9, optional spaces or hyphens between groups of 4.
    # Format only (no Verhoeff checksum) on purpose: for a BLOCKING control a fake or mistyped
    # number must still be caught.
    ("IN_AADHAAR", r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b", None, 0.85),
    # PAN: 5 capital letters, 4 digits, 1 capital letter.
    ("IN_PAN", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", None, 0.85),
    # Indian mobile number, optional +91 prefix.
    ("IN_MOBILE", r"(?<![\w+])(?:\+91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}(?!\d)", None, 0.8),
    # Payment card: 13-16 digits (spaces or hyphens allowed) that pass the Luhn check.
    ("CREDIT_CARD", r"\b(?:\d[ \-]?){12,15}\d\b", luhn_valid, 0.85),
]

# (name, regex string)
SECRET_SPECS = [
    ("AWS_ACCESS_KEY_ID", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
    (
        "AWS_SECRET_ACCESS_KEY",
        r"""(?i)\b(?:aws_?secret_?access_?key|secret_?access_?key)\b\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}""",
    ),
    ("PRIVATE_KEY_BLOCK", r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("GITHUB_TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("SLACK_TOKEN", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"),
    ("API_KEY_SK", r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    (
        "GENERIC_SECRET_ASSIGNMENT",
        r"(?i)\b(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|auth[_\-]?token|access[_\-]?key)\b\s*[:=]\s*\S+",
    ),
]

PII_VALIDATORS = {entity: validator for entity, _r, validator, _s in PII_SPECS if validator}
COMPILED_PII = [(entity, re.compile(regex, re.MULTILINE)) for entity, regex, _v, _s in PII_SPECS]
COMPILED_SECRETS = [(name, re.compile(regex)) for name, regex in SECRET_SPECS]
