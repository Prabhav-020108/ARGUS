import pytest
from cryptography.fernet import Fernet

from privacy.vault.vault import TokenVault


@pytest.fixture
def vault(tmp_path):
    """A throw-away vault so tests never touch the real privacy/vault/vault.db."""
    return TokenVault(db_path=tmp_path / "test_vault.db", key=Fernet.generate_key())
