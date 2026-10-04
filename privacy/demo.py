"""
Print what the airlock does to one finding (safe to run any time; uses a throw-away vault).

Run from the repo root (PowerShell):
    python -m privacy.demo
"""

import json
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

from privacy.airlock.airlock import run_airlock
from privacy.vault.vault import TokenVault


def main():
    raw = {
        "finding_id": "F-DEMO-1",
        "resource_id": "argus-test-pii-near-pb3882",
        "resource_type": "AWSS3Bucket",
        "attributes": {
            "name": "argus-test-pii-near-pb3882",
            "arn": "arn:aws:s3:::argus-test-pii-near-pb3882",
            "region": "us-east-1",
            "default_encryption": True,
            "encryption_algorithm": "AES256",
            "logging_enabled": False,
            "personal_data": True,
            "tags": {"owner": "meenal.sharma@example.in", "note": "AKIAIOSFODNN7EXAMPLE"},
            "user_data": "aadhaar 2345 6789 0123",
        },
    }
    with tempfile.TemporaryDirectory() as tmp:
        vault = TokenVault(db_path=Path(tmp) / "demo.db", key=Fernet.generate_key())
        record, receipt = run_airlock(raw, "dpdp.rule6_logging", vault=vault)
    print("=== What the generator is allowed to see ===")
    print(json.dumps(record, indent=2))
    print("=== Privacy receipt ===")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
