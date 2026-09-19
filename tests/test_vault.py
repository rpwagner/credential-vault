"""Offline tests for encrypted storage, master keys, and locking."""

from __future__ import annotations

import multiprocessing
import os
import time
from pathlib import Path
from unittest.mock import Mock

import keyring
import pytest
from conftest import FakeMasterKeyProvider, fast_backend
from keyring.errors import KeyringError

from credential_vault import (
    CredentialVault,
    MacOSKeychainMasterKeyProvider,
    UnsupportedPlatformError,
    VaultLockTimeout,
    VaultUnavailable,
)


def _hold_lock(path: str, ready, release) -> None:
    with CredentialVault(Path(path), None).locked():
        ready.set()
        release.wait(5)


def _rewrite_while_locked(path: str, data_path: str, ready) -> None:
    with CredentialVault(Path(path), None).locked():
        Path(data_path).write_text("partial")
        ready.set()
        time.sleep(0.2)
        Path(data_path).write_text("complete")


def test_initialize_generates_master_key_and_private_files(
    tmp_path, monkeypatch, capsys, caplog
):
    path = tmp_path / "private" / "credentials.cryptfile"
    provider = FakeMasterKeyProvider()
    monkeypatch.setattr(
        "credential_vault.vault.secrets.token_urlsafe",
        lambda _: "generated-master-secret",
    )

    vault = CredentialVault.initialize(
        path,
        master_key_provider=provider,
        backend_factory=fast_backend,
    )

    assert provider.key == "generated-master-secret"
    assert provider.set_values == ["generated-master-secret"]
    assert path.is_file()
    assert (path.stat().st_mode & 0o777) == 0o600
    assert (vault.lock_path.stat().st_mode & 0o777) == 0o600
    exposed = capsys.readouterr().out + capsys.readouterr().err + caplog.text
    assert "generated-master-secret" not in exposed
    assert "generated-master-secret" not in repr(vault)


def test_existing_master_is_reused(initialized_vault):
    vault, provider, path = initialized_vault
    original_key = provider.key
    provider.set_values.clear()

    reopened = CredentialVault.initialize(
        path,
        master_key_provider=provider,
        backend_factory=fast_backend,
    )

    assert provider.key == original_key
    assert provider.set_values == []
    reopened.set_password("service", "account", "synthetic-secret")
    assert vault.get_password("service", "account") == "synthetic-secret"


def test_existing_vault_without_master_fails_without_replacement(tmp_path):
    path = tmp_path / "credentials.cryptfile"
    original = b"existing-encrypted-bytes"
    path.write_bytes(original)
    provider = FakeMasterKeyProvider()

    with pytest.raises(VaultUnavailable, match="master key"):
        CredentialVault.initialize(
            path,
            master_key_provider=provider,
            backend_factory=fast_backend,
        )

    assert path.read_bytes() == original
    assert provider.key is None
    assert provider.set_values == []


def test_wrong_master_fails_without_replacing_vault(initialized_vault):
    _, _, path = initialized_vault
    original = path.read_bytes()

    with pytest.raises(VaultUnavailable, match="unlock") as caught:
        CredentialVault.open(
            path,
            master_key_provider=FakeMasterKeyProvider("wrong-master-secret"),
            backend_factory=fast_backend,
        )

    assert path.read_bytes() == original
    assert "wrong-master-secret" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_explicit_backend_ignores_environment_and_global_keyring(
    initialized_vault, monkeypatch
):
    vault, provider, path = initialized_vault
    vault.set_password("service", "account", "synthetic-secret")
    original_backend = keyring.get_keyring()
    monkeypatch.setenv("KEYRING_CRYPTFILE_PASSWORD", "wrong-environment-secret")

    reopened = CredentialVault.open(
        path,
        master_key_provider=provider,
        backend_factory=fast_backend,
    )

    assert reopened.get_password("service", "account") == "synthetic-secret"
    assert keyring.get_keyring() is original_backend


def test_static_secret_round_trip_is_encrypted(initialized_vault):
    vault, _, path = initialized_vault

    vault.set_password("example-service", "example-account", "synthetic-secret")

    assert (
        vault.get_password("example-service", "example-account") == "synthetic-secret"
    )
    assert b"synthetic-secret" not in path.read_bytes()
    assert vault.delete_password("example-service", "example-account") is True
    assert vault.delete_password("example-service", "example-account") is False
    assert vault.get_password("example-service", "example-account") is None


def test_backend_failures_are_redacted(tmp_path):
    backend = Mock()
    backend.get_password.side_effect = RuntimeError(
        "master-secret api-key access-token refresh-token"
    )
    vault = CredentialVault(tmp_path / "credentials.cryptfile", backend)

    with pytest.raises(VaultUnavailable) as caught:
        vault.get_password("service", "account")

    for secret in ("master-secret", "api-key", "access-token", "refresh-token"):
        assert secret not in str(caught.value)
    assert caught.value.__cause__ is None


def test_status_reports_only_non_secret_state(tmp_path):
    path = tmp_path / "credentials.cryptfile"
    provider = FakeMasterKeyProvider()
    assert (
        CredentialVault.status(
            path, master_key_provider=provider, backend_factory=fast_backend
        )
        == "missing"
    )
    CredentialVault.initialize(
        path, master_key_provider=provider, backend_factory=fast_backend
    )
    assert (
        CredentialVault.status(
            path, master_key_provider=provider, backend_factory=fast_backend
        )
        == "initialized"
    )
    assert (
        CredentialVault.status(
            path,
            master_key_provider=FakeMasterKeyProvider("wrong-master"),
            backend_factory=fast_backend,
        )
        == "unreadable"
    )


def test_macos_keychain_provider_uses_caller_identity_and_explicit_backend():
    backend = Mock()
    backend.get_password.return_value = "master"
    provider = MacOSKeychainMasterKeyProvider(
        "caller-service", "caller-account", backend=backend
    )

    assert provider.get_key() == "master"
    provider.set_key("new-master")
    provider.delete_key()

    backend.get_password.assert_called_once_with("caller-service", "caller-account")
    backend.set_password.assert_called_once_with(
        "caller-service", "caller-account", "new-master"
    )
    backend.delete_password.assert_called_once_with("caller-service", "caller-account")


def test_macos_provider_fails_clearly_off_macos(monkeypatch):
    monkeypatch.setattr("credential_vault.master_keys.sys.platform", "linux")
    with pytest.raises(UnsupportedPlatformError, match="macOS"):
        MacOSKeychainMasterKeyProvider("service", "account")


def test_macos_provider_redacts_backend_failure():
    backend = Mock()
    backend.get_password.side_effect = KeyringError("synthetic-master-secret")
    provider = MacOSKeychainMasterKeyProvider(
        "caller-service", "caller-account", backend=backend
    )

    with pytest.raises(VaultUnavailable) as caught:
        provider.get_key()

    assert "synthetic-master-secret" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_writer_exclusion_has_finite_timeout(tmp_path):
    context = multiprocessing.get_context("fork")
    path = tmp_path / "credentials.cryptfile"
    ready = context.Event()
    release = context.Event()
    process = context.Process(target=_hold_lock, args=(str(path), ready, release))
    process.start()
    assert ready.wait(5)
    try:
        contender = CredentialVault(path, None, lock_timeout=0.05)
        with (
            pytest.raises(VaultLockTimeout, match="Timed out") as caught,
            contender.locked(),
        ):
            pass
        assert str(path) not in str(caught.value)
    finally:
        release.set()
        process.join(5)
        if process.is_alive():
            process.terminate()
    assert process.exitcode == 0


def test_reader_waits_for_cooperating_writer(tmp_path):
    context = multiprocessing.get_context("fork")
    vault_path = tmp_path / "credentials.cryptfile"
    data_path = tmp_path / "rewrite-state"
    ready = context.Event()
    process = context.Process(
        target=_rewrite_while_locked,
        args=(str(vault_path), str(data_path), ready),
    )
    process.start()
    assert ready.wait(5)

    with CredentialVault(vault_path, None).locked():
        observed = data_path.read_text()
    process.join(5)

    assert process.exitcode == 0
    assert observed == "complete"


def test_lock_timeout_must_be_finite(tmp_path):
    for timeout in (-1, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="finite"):
            CredentialVault(tmp_path / "vault", None, lock_timeout=timeout)


def test_lock_file_is_never_unlinked(initialized_vault):
    vault, _, _ = initialized_vault
    lock_inode = os.stat(vault.lock_path).st_ino
    with vault.locked():
        pass
    assert vault.lock_path.exists()
    assert os.stat(vault.lock_path).st_ino == lock_inode
