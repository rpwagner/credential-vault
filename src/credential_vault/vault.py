"""Explicit encrypted credential vault with finite cooperative POSIX locking."""

from __future__ import annotations

import math
import os
import secrets
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only on unsupported Windows
    fcntl = None  # type: ignore[assignment]

from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from keyrings.cryptfile.cryptfile import CryptFileKeyring

from .errors import UnsupportedPlatformError, VaultLockTimeout, VaultUnavailable
from .master_keys import MasterKeyProvider

DEFAULT_LOCK_TIMEOUT = 5.0
VaultStatus = Literal["missing", "initialized", "unreadable"]
BackendFactory = Callable[[], KeyringBackend]


def _selected_path(path: str | Path) -> Path:
    return Path(path).expanduser()


class CredentialVault:
    """Compose one explicit encrypted backend with one cooperative lock."""

    def __init__(
        self,
        path: Path,
        backend: KeyringBackend | None,
        *,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
    ) -> None:
        if lock_timeout < 0 or not math.isfinite(lock_timeout):
            raise ValueError("lock_timeout must be a finite non-negative value")
        self.path = path
        self._backend = backend
        self.lock_timeout = lock_timeout

    def __repr__(self) -> str:
        return f"<{type(self).__name__} path={self.path!s}>"

    @property
    def lock_path(self) -> Path:
        """Return the stable adjacent lock-file path."""
        return self.path.with_name(f"{self.path.name}.lock")

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        master_key_provider: MasterKeyProvider,
        backend_factory: BackendFactory = CryptFileKeyring,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
    ) -> CredentialVault:
        """Open an initialized vault without creating credential state."""
        selected_path = _selected_path(path)
        vault = cls(selected_path, None, lock_timeout=lock_timeout)
        with vault.locked():
            master_key = master_key_provider.get_key()
            if master_key is None or not selected_path.is_file():
                raise VaultUnavailable("Credential vault is not initialized")
            vault._backend = _open_backend(selected_path, master_key, backend_factory)
            del master_key
        return vault

    @classmethod
    def initialize(
        cls,
        path: str | Path,
        *,
        master_key_provider: MasterKeyProvider,
        backend_factory: BackendFactory = CryptFileKeyring,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
    ) -> CredentialVault:
        """Initialize or validate a vault without replacing existing key material."""
        selected_path = _selected_path(path)
        vault = cls(selected_path, None, lock_timeout=lock_timeout)
        with vault.locked():
            vault_existed = selected_path.exists()
            master_key = master_key_provider.get_key()
            generated = False
            if master_key is None:
                if vault_existed:
                    raise VaultUnavailable(
                        "Credential vault exists but its master key is unavailable"
                    )
                master_key = secrets.token_urlsafe(48)
                master_key_provider.set_key(master_key)
                generated = True
            try:
                vault._backend = _open_backend(
                    selected_path, master_key, backend_factory
                )
                os.chmod(selected_path, 0o600)
            except (VaultUnavailable, OSError) as error:
                if generated:
                    try:
                        master_key_provider.delete_key()
                    except Exception:  # noqa: BLE001 - redact provider failures
                        raise VaultUnavailable(
                            "Unable to roll back vault master key"
                        ) from None
                if isinstance(error, VaultUnavailable):
                    raise
                raise VaultUnavailable("Unable to secure credential vault") from None
            finally:
                del master_key
        return vault

    @classmethod
    def status(
        cls,
        path: str | Path,
        *,
        master_key_provider: MasterKeyProvider,
        backend_factory: BackendFactory = CryptFileKeyring,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
    ) -> VaultStatus:
        """Return only non-secret initialization state."""
        selected_path = _selected_path(path)
        vault = cls(selected_path, None, lock_timeout=lock_timeout)
        with vault.locked():
            master_key = master_key_provider.get_key()
            if master_key is None:
                return "unreadable" if selected_path.exists() else "missing"
            if not selected_path.is_file():
                return "missing"
            try:
                _open_backend(selected_path, master_key, backend_factory)
            except VaultUnavailable:
                return "unreadable"
            finally:
                del master_key
            return "initialized"

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Hold the vault's finite advisory-lock transaction boundary."""
        if fcntl is None:
            raise UnsupportedPlatformError(
                "Credential vault locking requires a POSIX platform"
            )
        try:
            self.lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            os.chmod(self.lock_path, 0o600)
        except OSError:
            raise VaultUnavailable("Unable to open credential vault lock") from None

        deadline = time.monotonic() + self.lock_timeout
        acquired = False
        try:
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise VaultLockTimeout(
                            "Timed out waiting for credential vault lock"
                        ) from None
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
                except OSError:
                    raise VaultUnavailable(
                        "Unable to acquire credential vault lock"
                    ) from None
            yield
        finally:
            try:
                if acquired:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def get_password(self, service: str, account: str) -> str | None:
        """Return an opaque secret, or ``None`` when no value is stored."""
        with self.locked():
            return self._get_password_unlocked(service, account)

    def set_password(self, service: str, account: str, value: str) -> None:
        """Store an opaque secret."""
        with self.locked():
            self._set_password_unlocked(service, account, value)

    def delete_password(self, service: str, account: str) -> bool:
        """Delete an opaque secret, returning whether one existed."""
        with self.locked():
            return self._delete_password_unlocked(service, account)

    def _required_backend(self) -> KeyringBackend:
        if self._backend is None:
            raise VaultUnavailable("Credential vault is not open")
        return self._backend

    def _get_password_unlocked(self, service: str, account: str) -> str | None:
        try:
            return self._required_backend().get_password(service, account)
        except Exception:  # noqa: BLE001 - redact explicit backend failures
            raise VaultUnavailable("Unable to read credential vault") from None

    def _set_password_unlocked(self, service: str, account: str, value: str) -> None:
        try:
            self._required_backend().set_password(service, account, value)
            os.chmod(self.path, 0o600)
        except Exception:  # noqa: BLE001 - redact explicit backend failures
            raise VaultUnavailable("Unable to write credential vault") from None

    def _delete_password_unlocked(self, service: str, account: str) -> bool:
        backend = self._required_backend()
        try:
            if backend.get_password(service, account) is None:
                return False
            backend.delete_password(service, account)
            os.chmod(self.path, 0o600)
        except PasswordDeleteError:
            return False
        except Exception:  # noqa: BLE001 - redact explicit backend failures
            raise VaultUnavailable("Unable to delete from credential vault") from None
        return True


def _open_backend(
    path: Path,
    master_key: str,
    backend_factory: BackendFactory,
) -> KeyringBackend:
    try:
        backend = backend_factory()
        backend.file_path = str(path)
        backend.keyring_key = master_key
        return backend
    except Exception:  # noqa: BLE001 - backend initialization errors vary
        raise VaultUnavailable("Unable to unlock credential vault") from None
