from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from keyrings.cryptfile.cryptfile import CryptFileKeyring

from credential_vault import CredentialVault


@dataclass
class FakeMasterKeyProvider:
    key: str | None = None
    set_values: list[str] = field(default_factory=list)
    delete_count: int = 0

    def get_key(self) -> str | None:
        return self.key

    def set_key(self, value: str) -> None:
        self.key = value
        self.set_values.append(value)

    def delete_key(self) -> None:
        self.key = None
        self.delete_count += 1


def fast_backend() -> CryptFileKeyring:
    backend = CryptFileKeyring()
    backend.time_cost = 1
    backend.memory_cost = 1024
    backend.parallelism = 1
    return backend


@pytest.fixture
def initialized_vault(tmp_path):
    provider = FakeMasterKeyProvider()
    path = tmp_path / "credentials.cryptfile"
    vault = CredentialVault.initialize(
        path,
        master_key_provider=provider,
        backend_factory=fast_backend,
    )
    return vault, provider, path
