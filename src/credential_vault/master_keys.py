"""Master-key provider contracts and platform-specific implementations."""

from __future__ import annotations

import sys
from typing import Protocol

from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

from .errors import UnsupportedPlatformError, VaultUnavailable


class MasterKeyProvider(Protocol):
    """Supply a vault master secret from a trusted host mechanism."""

    def get_key(self) -> str | None:
        """Return the master secret, or ``None`` when it is absent."""
        ...

    def set_key(self, value: str) -> None:
        """Persist a newly generated master secret."""
        ...

    def delete_key(self) -> None:
        """Remove a master secret created during failed initialization."""
        ...


class MacOSKeychainMasterKeyProvider:
    """Store a vault master secret in an explicitly selected macOS Keychain item."""

    def __init__(
        self,
        service: str,
        account: str,
        *,
        backend: KeyringBackend | None = None,
    ) -> None:
        if not service or not account:
            raise ValueError("Keychain service and account must be non-empty")
        if backend is None:
            if sys.platform != "darwin":
                raise UnsupportedPlatformError(
                    "macOS Keychain master-key storage is unavailable"
                )
            try:
                from keyring.backends.macOS import Keyring as MacOSKeyring

                backend = MacOSKeyring()
            except Exception:  # noqa: BLE001 - redact backend/import failures
                raise VaultUnavailable("Unable to access vault master key") from None
        self._service = service
        self._account = account
        self._backend = backend

    def get_key(self) -> str | None:
        try:
            return self._backend.get_password(self._service, self._account)
        except Exception:  # noqa: BLE001 - keyring backends do not share one error type
            raise VaultUnavailable("Unable to access vault master key") from None

    def set_key(self, value: str) -> None:
        try:
            self._backend.set_password(self._service, self._account, value)
        except Exception:  # noqa: BLE001 - keyring backends do not share one error type
            raise VaultUnavailable("Unable to store vault master key") from None

    def delete_key(self) -> None:
        try:
            self._backend.delete_password(self._service, self._account)
        except PasswordDeleteError:
            return
        except Exception:  # noqa: BLE001 - keyring backends do not share one error type
            raise VaultUnavailable("Unable to remove vault master key") from None
