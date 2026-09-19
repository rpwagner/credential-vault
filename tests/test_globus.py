"""Offline tests for Globus SDK storage and lifecycle composition."""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from conftest import FakeMasterKeyProvider, fast_backend
from globus_sdk import AuthAPIError, GlobusError
from globus_sdk.gare import GlobusAuthorizationParameters
from globus_sdk.token_storage import TokenStorageData, TokenValidationError
from requests import PreparedRequest, Response

from credential_vault import (
    CredentialNotFound,
    CredentialVault,
    GlobusAuthenticationError,
    GlobusTokenManager,
    ReauthenticationRequired,
    VaultTokenStorage,
    VaultUnavailable,
)
from credential_vault.globus import _GLOBUS_TOKEN_SERVICE


def _token(resource_server: str, access_token: str) -> TokenStorageData:
    return TokenStorageData(
        resource_server=resource_server,
        identity_id="synthetic-identity",
        scope="scope-a scope-b",
        access_token=access_token,
        refresh_token=f"refresh-{access_token}",
        expires_at_seconds=2_000_000_000,
        token_type="Bearer",
    )


def _store_token(path: str, key: str, resource_server: str, start) -> None:
    provider = FakeMasterKeyProvider(key)
    vault = CredentialVault.open(
        Path(path),
        master_key_provider=provider,
        backend_factory=fast_backend,
    )
    start.wait(5)
    VaultTokenStorage("concurrent", vault=vault).store_token_data_by_resource_server(
        {resource_server: _token(resource_server, f"access-{resource_server}")}
    )


def _manager(vault: CredentialVault) -> GlobusTokenManager:
    return GlobusTokenManager(
        app_name="caller-app",
        native_client_id="synthetic-client-id",
        resource_server="synthetic-resource-server",
        scopes=("scope-a", "scope-b"),
        namespace="caller-namespace",
        vault=vault,
    )


def _auth_api_error(error_code: str, secret: str) -> AuthAPIError:
    response = Response()
    response.status_code = 400
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps(
        {"error": error_code, "error_description": secret}
    ).encode()
    request = PreparedRequest()
    request.prepare(method="POST", url="https://auth.globus.org/v2/oauth2/token")
    response.request = request
    return AuthAPIError(response)


def test_token_storage_round_trip_merge_and_namespace_isolation(initialized_vault):
    vault, _, path = initialized_vault
    first = VaultTokenStorage("first", vault=vault)
    second = VaultTokenStorage("second", vault=vault)
    token_a = _token("resource-a", "synthetic-access-a")
    token_b = _token("resource-b", "synthetic-access-b")

    first.store_token_data_by_resource_server(
        {"resource-a": token_a, "resource-b": token_b}
    )
    second.store_token_data_by_resource_server(
        {"resource-a": _token("resource-a", "synthetic-second")}
    )
    replacement = _token("resource-a", "synthetic-replacement")
    first.store_token_data_by_resource_server({"resource-a": replacement})

    restored = first.get_token_data_by_resource_server()
    assert restored["resource-a"].to_dict() == replacement.to_dict()
    assert restored["resource-b"].to_dict() == token_b.to_dict()
    assert second.get_token_data("resource-a").access_token == "synthetic-second"
    assert b"synthetic-access" not in path.read_bytes()


def test_remove_preserves_unrelated_records(initialized_vault):
    vault, _, _ = initialized_vault
    storage = VaultTokenStorage("test", vault=vault)
    storage.store_token_data_by_resource_server(
        {
            "resource-a": _token("resource-a", "access-a"),
            "resource-b": _token("resource-b", "access-b"),
        }
    )

    assert storage.remove_token_data("resource-a") is True
    assert set(storage.get_token_data_by_resource_server()) == {"resource-b"}
    assert storage.remove_token_data("missing") is False
    assert storage.remove_token_data("resource-b") is True
    assert storage.get_token_data_by_resource_server() == {}


@pytest.mark.parametrize(
    "value",
    ["synthetic-token-not-json", json.dumps({"resource": {"access_token": "secret"}})],
)
def test_malformed_token_data_is_redacted(initialized_vault, value):
    vault, _, _ = initialized_vault
    vault.set_password(_GLOBUS_TOKEN_SERVICE, "test", value)

    with pytest.raises(VaultUnavailable, match="malformed") as caught:
        VaultTokenStorage("test", vault=vault).get_token_data_by_resource_server()

    assert "synthetic-token" not in str(caught.value)
    assert "secret" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_concurrent_token_updates_preserve_both_resources(initialized_vault):
    _, provider, path = initialized_vault
    context = multiprocessing.get_context("fork")
    start = context.Event()
    processes = [
        context.Process(
            target=_store_token,
            args=(str(path), provider.key, resource_server, start),
        )
        for resource_server in ("resource-a", "resource-b")
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(10)
        if process.is_alive():
            process.terminate()
        assert process.exitcode == 0

    reopened = CredentialVault.open(
        path,
        master_key_provider=provider,
        backend_factory=fast_backend,
    )
    restored = VaultTokenStorage(
        "concurrent", vault=reopened
    ).get_token_data_by_resource_server()
    assert set(restored) == {"resource-a", "resource-b"}


def test_current_token_uses_sdk_authorizer_without_login(initialized_vault):
    vault, _, _ = initialized_vault
    manager = _manager(vault)
    VaultTokenStorage(
        manager.namespace, vault=vault
    ).store_token_data_by_resource_server(
        {manager.resource_server: _token(manager.resource_server, "stored-access")}
    )
    original_locked = vault.locked
    vault.locked = Mock(side_effect=original_locked)
    app = Mock()
    app.__enter__ = Mock(return_value=app)
    app.__exit__ = Mock(return_value=None)
    app.get_authorizer.return_value.get_authorization_header.return_value = (
        "Bearer current-access-token"
    )

    with patch("credential_vault.globus.UserApp", return_value=app) as user_app:
        assert manager.current_access_token() == "current-access-token"

    assert vault.locked.call_count == 1
    config = user_app.call_args.kwargs["config"]
    assert config.request_refresh_tokens is True
    assert config.token_validation_error_handler is None
    assert config.token_storage._lock_operations is False
    app.login.assert_not_called()


def test_sdk_driven_refresh_persists_for_subsequent_consumer(initialized_vault):
    vault, _, _ = initialized_vault
    manager = _manager(vault)
    VaultTokenStorage(
        manager.namespace, vault=vault
    ).store_token_data_by_resource_server(
        {manager.resource_server: _token(manager.resource_server, "expired-access")}
    )
    app = Mock()
    app.__enter__ = Mock(return_value=app)
    app.__exit__ = Mock(return_value=None)

    def refresh_and_return_header():
        app.config.token_storage.store_token_data_by_resource_server(
            {
                manager.resource_server: _token(
                    manager.resource_server, "refreshed-access"
                )
            }
        )
        return "Bearer refreshed-access"

    app.get_authorizer.return_value.get_authorization_header.side_effect = (
        refresh_and_return_header
    )

    def build_app(*args, **kwargs):
        app.config = kwargs["config"]
        return app

    with patch("credential_vault.globus.UserApp", side_effect=build_app):
        assert manager.current_access_token() == "refreshed-access"

    stored = VaultTokenStorage(manager.namespace, vault=vault).get_token_data(
        manager.resource_server
    )
    assert stored.access_token == "refreshed-access"
    assert stored.refresh_token == "refresh-refreshed-access"


def test_missing_token_does_not_start_login(initialized_vault):
    vault, _, _ = initialized_vault
    with (
        patch("credential_vault.globus.UserApp") as user_app,
        pytest.raises(CredentialNotFound, match="not found"),
    ):
        _manager(vault).current_access_token()
    user_app.assert_not_called()


def test_invalid_stored_token_requires_explicit_login(initialized_vault):
    vault, _, _ = initialized_vault
    manager = _manager(vault)
    VaultTokenStorage(
        manager.namespace, vault=vault
    ).store_token_data_by_resource_server(
        {manager.resource_server: _token(manager.resource_server, "stored-access")}
    )
    app = Mock()
    app.__enter__ = Mock(return_value=app)
    app.__exit__ = Mock(return_value=None)
    app.get_authorizer.side_effect = TokenValidationError(
        "stored synthetic-access-token was invalid"
    )

    with (
        patch("credential_vault.globus.UserApp", return_value=app),
        pytest.raises(ReauthenticationRequired) as caught,
    ):
        manager.current_access_token()

    assert "synthetic-access-token" not in str(caught.value)
    assert caught.value.__cause__ is None
    app.login.assert_not_called()


def test_generic_globus_failure_is_redacted(initialized_vault):
    vault, _, _ = initialized_vault
    manager = _manager(vault)
    VaultTokenStorage(
        manager.namespace, vault=vault
    ).store_token_data_by_resource_server(
        {manager.resource_server: _token(manager.resource_server, "stored-access")}
    )
    app = Mock()
    app.__enter__ = Mock(return_value=app)
    app.__exit__ = Mock(return_value=None)
    app.get_authorizer.return_value.get_authorization_header.side_effect = GlobusError(
        "response exposed synthetic-access-token"
    )

    with (
        patch("credential_vault.globus.UserApp", return_value=app),
        pytest.raises(GlobusAuthenticationError) as caught,
    ):
        manager.current_access_token()

    assert "synthetic-access-token" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_revoked_refresh_grant_requires_reauthentication(initialized_vault):
    vault, _, _ = initialized_vault
    manager = _manager(vault)
    VaultTokenStorage(
        manager.namespace, vault=vault
    ).store_token_data_by_resource_server(
        {manager.resource_server: _token(manager.resource_server, "stored-access")}
    )
    app = Mock()
    app.__enter__ = Mock(return_value=app)
    app.__exit__ = Mock(return_value=None)
    app.get_authorizer.return_value.get_authorization_header.side_effect = (
        _auth_api_error("invalid_grant", "synthetic-revoked-refresh-token")
    )

    with (
        patch("credential_vault.globus.UserApp", return_value=app),
        pytest.raises(ReauthenticationRequired) as caught,
    ):
        manager.current_access_token()

    assert "synthetic-revoked-refresh-token" not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("authorization", [None, "", "Basic value", "Bearer "])
def test_non_bearer_result_requires_login(initialized_vault, authorization):
    vault, _, _ = initialized_vault
    manager = _manager(vault)
    VaultTokenStorage(
        manager.namespace, vault=vault
    ).store_token_data_by_resource_server(
        {manager.resource_server: _token(manager.resource_server, "stored-access")}
    )
    app = Mock()
    app.__enter__ = Mock(return_value=app)
    app.__exit__ = Mock(return_value=None)
    app.get_authorizer.return_value.get_authorization_header.return_value = (
        authorization
    )

    with (
        patch("credential_vault.globus.UserApp", return_value=app),
        pytest.raises(ReauthenticationRequired),
    ):
        manager.current_access_token()


def test_explicit_login_passes_session_policy_and_persists(initialized_vault):
    vault, _, _ = initialized_vault
    auth_params = GlobusAuthorizationParameters(
        session_required_policies=["synthetic-policy"],
        session_required_mfa=True,
    )
    manager = GlobusTokenManager(
        app_name="caller-app",
        native_client_id="synthetic-client-id",
        resource_server="synthetic-resource-server",
        scopes=("scope-a",),
        namespace="caller-namespace",
        vault=vault,
        authorization_parameters=auth_params,
    )
    app = Mock()
    app.__enter__ = Mock(return_value=app)
    app.__exit__ = Mock(return_value=None)

    def persist_login(*, auth_params, force):
        assert auth_params is manager.authorization_parameters
        assert force is True
        app.config.token_storage.store_token_data_by_resource_server(
            {manager.resource_server: _token(manager.resource_server, "login-access")}
        )

    app.login.side_effect = persist_login

    def build_app(*args, **kwargs):
        app.config = kwargs["config"]
        return app

    with patch("credential_vault.globus.UserApp", side_effect=build_app):
        manager.login()

    stored = VaultTokenStorage(manager.namespace, vault=vault).get_token_data(
        manager.resource_server
    )
    assert stored.access_token == "login-access"


def test_failed_login_preserves_existing_tokens(initialized_vault):
    vault, _, _ = initialized_vault
    manager = _manager(vault)
    storage = VaultTokenStorage(manager.namespace, vault=vault)
    original = _token(manager.resource_server, "existing-access")
    storage.store_token_data_by_resource_server({manager.resource_server: original})
    app = Mock()
    app.__enter__ = Mock(return_value=app)
    app.__exit__ = Mock(return_value=None)
    app.login.side_effect = GlobusError("failed with synthetic-refresh-token")

    with (
        patch("credential_vault.globus.UserApp", return_value=app),
        pytest.raises(GlobusAuthenticationError) as caught,
    ):
        manager.login()

    assert "synthetic-refresh-token" not in str(caught.value)
    assert (
        storage.get_token_data(manager.resource_server).to_dict() == original.to_dict()
    )


def test_custom_login_failure_is_redacted(initialized_vault):
    vault, _, _ = initialized_vault
    manager = _manager(vault)
    app = Mock()
    app.__enter__ = Mock(return_value=app)
    app.__exit__ = Mock(return_value=None)
    app.login.side_effect = RuntimeError("failed with synthetic-access-token")

    with (
        patch("credential_vault.globus.UserApp", return_value=app),
        pytest.raises(GlobusAuthenticationError) as caught,
    ):
        manager.login()

    assert "synthetic-access-token" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_manager_repr_does_not_contain_tokens(initialized_vault):
    vault, _, _ = initialized_vault
    manager = _manager(vault)
    assert "access-token" not in repr(manager)
    assert "refresh-token" not in repr(manager)
