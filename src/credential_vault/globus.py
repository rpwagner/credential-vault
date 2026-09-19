"""Globus SDK token storage and token-lifecycle composition."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from globus_sdk import AuthAPIError, GlobusError, UserApp
from globus_sdk.gare import GlobusAuthorizationParameters
from globus_sdk.globus_app import GlobusAppConfig
from globus_sdk.token_storage import (
    TokenStorage,
    TokenStorageData,
    TokenValidationError,
)

from .errors import (
    CredentialNotFound,
    GlobusAuthenticationError,
    ReauthenticationRequired,
    VaultUnavailable,
)
from .vault import CredentialVault

_GLOBUS_TOKEN_SERVICE = "credential-vault/globus-tokens"


def _is_invalid_grant(error: AuthAPIError) -> bool:
    """Classify the SDK's OAuth grant failure without exposing its response."""
    raw_json = error.raw_json
    return error.code == "invalid_grant" or (
        isinstance(raw_json, dict) and raw_json.get("error") == "invalid_grant"
    )


class VaultTokenStorage(TokenStorage):
    """Persist Globus SDK token data in an explicit encrypted vault."""

    def __init__(
        self,
        namespace: str,
        *,
        vault: CredentialVault,
        lock_operations: bool = True,
    ) -> None:
        if not namespace:
            raise ValueError("namespace must be non-empty")
        super().__init__(namespace)
        self._vault = vault
        self._lock_operations = lock_operations

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        if self._lock_operations:
            with self._vault.locked():
                yield
        else:
            yield

    def _read_serialized(self) -> dict[str, dict[str, Any]]:
        serialized = self._vault._get_password_unlocked(
            _GLOBUS_TOKEN_SERVICE, self.namespace
        )
        if serialized is None:
            return {}
        try:
            data = json.loads(serialized)
            if not isinstance(data, dict) or not all(
                isinstance(resource_server, str) and isinstance(token_data, dict)
                for resource_server, token_data in data.items()
            ):
                raise TypeError
        except (json.JSONDecodeError, TypeError):
            raise VaultUnavailable("Stored Globus token data is malformed") from None
        return data

    def _write_serialized(self, data: Mapping[str, dict[str, Any]]) -> None:
        try:
            serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            raise VaultUnavailable("Unable to serialize Globus token data") from None
        self._vault._set_password_unlocked(
            _GLOBUS_TOKEN_SERVICE, self.namespace, serialized
        )

    def store_token_data_by_resource_server(
        self, token_data_by_resource_server: Mapping[str, TokenStorageData]
    ) -> None:
        """Merge SDK token records in one locked read/write transaction."""
        with self._transaction():
            data = self._read_serialized()
            try:
                data.update(
                    {
                        resource_server: token_data.to_dict()
                        for resource_server, token_data in token_data_by_resource_server.items()
                    }
                )
            except (AttributeError, TypeError, ValueError):
                raise VaultUnavailable(
                    "Unable to serialize Globus token data"
                ) from None
            self._write_serialized(data)

    def get_token_data_by_resource_server(self) -> dict[str, TokenStorageData]:
        """Return all SDK token records in the current namespace."""
        with self._transaction():
            data = self._read_serialized()
            try:
                return {
                    resource_server: TokenStorageData.from_dict(token_data)
                    for resource_server, token_data in data.items()
                }
            except (KeyError, TypeError, ValueError):
                raise VaultUnavailable(
                    "Stored Globus token data is malformed"
                ) from None

    def remove_token_data(self, resource_server: str) -> bool:
        """Remove one SDK token record while preserving unrelated records."""
        with self._transaction():
            data = self._read_serialized()
            if resource_server not in data:
                return False
            del data[resource_server]
            if data:
                self._write_serialized(data)
            else:
                self._vault._delete_password_unlocked(
                    _GLOBUS_TOKEN_SERVICE, self.namespace
                )
            return True


@dataclass(frozen=True)
class GlobusTokenManager:
    """Resolve and explicitly establish reusable Globus user authorization."""

    app_name: str
    native_client_id: str
    resource_server: str
    scopes: Sequence[str]
    namespace: str
    vault: CredentialVault
    authorization_parameters: GlobusAuthorizationParameters | None = None
    login_flow_manager: Any = None
    login_redirect_uri: str | None = None

    def _storage(self, *, lock_operations: bool = False) -> VaultTokenStorage:
        return VaultTokenStorage(
            self.namespace,
            vault=self.vault,
            lock_operations=lock_operations,
        )

    def _config(self, storage: VaultTokenStorage) -> GlobusAppConfig:
        return GlobusAppConfig(
            login_flow_manager=self.login_flow_manager,
            login_redirect_uri=self.login_redirect_uri,
            token_storage=storage,
            request_refresh_tokens=True,
            token_validation_error_handler=None,
        )

    def _app(self, storage: VaultTokenStorage) -> UserApp:
        return UserApp(
            self.app_name,
            client_id=self.native_client_id,
            scope_requirements={self.resource_server: self.scopes},
            config=self._config(storage),
        )

    def current_access_token(self) -> str:
        """Return a current token, allowing only SDK-managed refresh, never login."""
        storage = self._storage()
        try:
            with self.vault.locked():
                if storage.get_token_data(self.resource_server) is None:
                    raise CredentialNotFound("Globus credential was not found")
                with self._app(storage) as app:
                    authorization = app.get_authorizer(
                        self.resource_server
                    ).get_authorization_header()
        except CredentialNotFound:
            raise
        except TokenValidationError:
            raise ReauthenticationRequired(
                "Globus credential requires explicit login"
            ) from None
        except AuthAPIError as error:
            if _is_invalid_grant(error):
                raise ReauthenticationRequired(
                    "Globus credential requires explicit login"
                ) from None
            raise GlobusAuthenticationError(
                "Unable to resolve Globus credential"
            ) from None
        except GlobusError:
            raise GlobusAuthenticationError(
                "Unable to resolve Globus credential"
            ) from None

        prefix = "Bearer "
        if not authorization or not authorization.startswith(prefix):
            raise ReauthenticationRequired("Globus credential requires explicit login")
        access_token = authorization[len(prefix) :]
        if not access_token:
            raise ReauthenticationRequired("Globus credential requires explicit login")
        return access_token

    def login(
        self,
        *,
        authorization_parameters: GlobusAuthorizationParameters | None = None,
    ) -> None:
        """Run an explicit SDK login and persist tokens only after its success."""
        storage = self._storage(lock_operations=True)
        selected_parameters = (
            authorization_parameters
            if authorization_parameters is not None
            else self.authorization_parameters
        )
        try:
            with self._app(storage) as app:
                app.login(auth_params=selected_parameters, force=True)
        except TokenValidationError:
            raise ReauthenticationRequired(
                "Globus login did not establish usable authorization"
            ) from None
        except GlobusError:
            raise GlobusAuthenticationError("Globus login failed") from None
        except Exception:  # noqa: BLE001 - custom SDK login managers vary
            raise GlobusAuthenticationError("Globus login failed") from None
