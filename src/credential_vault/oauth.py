"""Authlib-backed user authorization, with encrypted on-demand token storage."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import requests
from authlib.common.security import generate_token
from authlib.integrations.base_client import OAuthError
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc6749 import OAuth2Token
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oidc.core import CodeIDToken
from authlib.oidc.discovery import OpenIDProviderMetadata
from joserfc import jwt
from joserfc.jwk import KeySet

from .errors import (
    CredentialError, CredentialNotFound, OAuthAuthenticationError,
    ReauthenticationRequired, VaultUnavailable,
)
from .loopback import LoopbackRedirect
from .vault import CredentialVault

_OAUTH_TOKEN_SERVICE = "credential-vault/oauth-tokens"
_RESERVED_PARAMETERS = frozenset({
    "client_id", "client_secret", "redirect_uri", "response_type", "state",
    "nonce", "code_challenge", "code_challenge_method", "code_verifier",
    "code", "access_token", "refresh_token", "id_token", "scope",
})


def _https_url(value: str) -> None:
    parts = urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or parts.username
            or parts.password or parts.fragment or parts.query):
        raise ValueError("OAuth endpoints must be HTTPS URLs without credentials or query")
    parts.port  # Validate the port without displaying the URL.


@dataclass(frozen=True, repr=False)
class OAuthClientConfig:
    """Caller-owned endpoints and client policy; contains no client secret.

    Discovery requires an explicit expected issuer. Public clients use S256;
    confidential clients may select client_secret_basic or client_secret_post.
    OIDC uses a caller-selected asymmetric signing algorithm allowlist.
    """

    client_id: str
    redirect_uri: str
    scope: str
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    metadata_url: str | None = None
    issuer: str | None = None
    jwks_uri: str | None = None
    token_endpoint_auth_method: str = "none"
    pkce: bool = True
    oidc: bool = False
    id_token_algorithms: tuple[str, ...] = ("RS256",)
    timeout: float = 30.0
    leeway: float = 60.0

    def __post_init__(self) -> None:
        try:
            if not self.client_id or not self.redirect_uri:
                raise ValueError
            if not math.isfinite(self.timeout) or self.timeout <= 0:
                raise ValueError
            if not math.isfinite(self.leeway) or self.leeway < 0:
                raise ValueError
            if self.token_endpoint_auth_method not in {
                "none", "client_secret_basic", "client_secret_post",
            }:
                raise ValueError
            if self.token_endpoint_auth_method == "none" and not self.pkce:
                raise ValueError
            if self.metadata_url:
                if not self.issuer or self.authorization_endpoint or self.token_endpoint:
                    raise ValueError
            elif not self.authorization_endpoint or not self.token_endpoint:
                raise ValueError
            if self.oidc and (not self.issuer or "openid" not in self.scope.split()
                              or not (self.metadata_url or self.jwks_uri)):
                raise ValueError
            allowed = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                       "ES256", "ES384", "ES512", "EdDSA"}
            if not self.id_token_algorithms or not set(self.id_token_algorithms) <= allowed:
                raise ValueError
            for value in (self.authorization_endpoint, self.token_endpoint,
                          self.metadata_url, self.issuer, self.jwks_uri):
                if value:
                    _https_url(value)
            redirect = urlsplit(self.redirect_uri)
            if (redirect.username or redirect.password or redirect.query or redirect.fragment
                    or not redirect.hostname or not redirect.path.startswith("/")):
                raise ValueError
            if redirect.scheme != "https" and not (
                redirect.scheme == "http" and redirect.hostname in {"127.0.0.1", "localhost", "::1"}
            ):
                raise ValueError
            redirect.port
        except Exception:
            raise ValueError("Invalid OAuth client configuration") from None


@dataclass(frozen=True, repr=False)
class OAuthTokenManager:
    """Resolve tokens without login; explicitly establish user authorization.

    Secret providers and session configuration hooks run in the trusted caller
    process. Hooks may configure Authlib compliance handling, but must not log
    secrets, weaken TLS, or change the selected client/endpoint authority.
    """

    config: OAuthClientConfig
    namespace: str
    vault: CredentialVault
    client_secret_provider: Callable[[], str] | None = field(default=None, repr=False)
    configure_session: Callable[[OAuth2Session], None] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.namespace:
            raise ValueError("namespace must be non-empty")
        confidential = self.config.token_endpoint_auth_method != "none"
        if confidential != (self.client_secret_provider is not None):
            raise ValueError("Client secret provider must match client authentication")

    def _metadata(self) -> dict[str, Any]:
        config = self.config
        if config.metadata_url:
            metadata_type = OpenIDProviderMetadata if config.oidc else AuthorizationServerMetadata
            metadata = metadata_type(self._get_json(config.metadata_url))
            metadata.validate()
            if metadata.get("issuer") != config.issuer:
                raise OAuthAuthenticationError("OAuth metadata issuer did not match")
        else:
            metadata = {
                "authorization_endpoint": config.authorization_endpoint,
                "token_endpoint": config.token_endpoint,
                "issuer": config.issuer, "jwks_uri": config.jwks_uri,
            }
        for name in ("authorization_endpoint", "token_endpoint"):
            _https_url(metadata[name])
        if config.oidc:
            _https_url(metadata["jwks_uri"])
        return dict(metadata)

    def _get_json(self, url: str) -> dict[str, Any]:
        # Separate, unauthenticated transport: never send token/client credentials
        # to discovery or JWKS, including netrc credentials or redirect targets.
        with requests.Session() as session:
            session.trust_env = False
            response = session.get(url, timeout=self.config.timeout, allow_redirects=False)
            if response.status_code != 200:
                raise OAuthAuthenticationError("Unable to load OAuth metadata")
            value = response.json()
            if not isinstance(value, dict):
                raise OAuthAuthenticationError("OAuth metadata is malformed")
            return value

    def _session(self, metadata, *, token=None, redirect_uri=None) -> OAuth2Session:
        secret = self.client_secret_provider() if self.client_secret_provider else None
        if self.client_secret_provider and (not isinstance(secret, str) or not secret):
            raise OAuthAuthenticationError("OAuth client secret is unavailable")
        session = OAuth2Session(
            self.config.client_id, secret,
            scope=self.config.scope, token=token,
            redirect_uri=redirect_uri or self.config.redirect_uri,
            token_endpoint_auth_method=self.config.token_endpoint_auth_method,
            code_challenge_method="S256" if self.config.pkce else None,
            token_endpoint=metadata["token_endpoint"],
            default_timeout=self.config.timeout, leeway=self.config.leeway,
        )
        session.trust_env = False
        if self.configure_session:
            try:
                self.configure_session(session)
            except Exception:
                session.close()
                raise OAuthAuthenticationError("Unable to configure OAuth session") from None
        return session

    @staticmethod
    def _validate_token(token: Any) -> None:
        if not isinstance(token, dict):
            raise ValueError
        if not isinstance(token.get("access_token"), str) or not token["access_token"]:
            raise ValueError
        if str(token.get("token_type", "")).lower() != "bearer":
            raise ValueError
        for name in ("refresh_token", "id_token"):
            if name in token and (not isinstance(token[name], str) or not token[name]):
                raise ValueError
        if "expires_at" in token and (not isinstance(token["expires_at"], int)
                                      or isinstance(token["expires_at"], bool)):
            raise ValueError
        for name in ("expires_at", "expires_in"):
            if name in token and (isinstance(token[name], bool)
                                  or not math.isfinite(float(token[name]))):
                raise ValueError
        # Authlib normalizes expires_in on receipt. Re-normalizing relative
        # expiry on each vault read would extend an expired credential forever.
        if "expires_in" in token and "expires_at" not in token:
            raise ValueError

    def _read(self) -> dict[str, Any]:
        serialized = self.vault._get_password_unlocked(_OAUTH_TOKEN_SERVICE, self.namespace)
        if serialized is None:
            raise CredentialNotFound("OAuth credential was not found")
        try:
            record = json.loads(serialized)
            self._validate_token(record["token"])
            if self.config.oidc and not all(
                isinstance(record.get(name), str) and record[name]
                for name in ("oidc_subject", "oidc_nonce")
            ):
                raise ValueError
            return record
        except Exception:
            raise VaultUnavailable("Stored OAuth token data is malformed") from None

    def _write(self, record: dict[str, Any]) -> None:
        try:
            self._validate_token(record["token"])
            serialized = json.dumps(record, separators=(",", ":"), allow_nan=False)
        except Exception:
            raise OAuthAuthenticationError("OAuth token response is malformed") from None
        self.vault._set_password_unlocked(_OAUTH_TOKEN_SERVICE, self.namespace, serialized)

    def _validate_id_token(self, token, metadata, *, nonce, subject=None, require_nonce=True) -> str:
        # Supported Authlib composition, using its maintained JOSE dependency.
        keys = KeySet.import_key_set(self._get_json(metadata["jwks_uri"]))
        decoded = jwt.decode(token["id_token"], keys, algorithms=list(self.config.id_token_algorithms))
        params = {"client_id": self.config.client_id, "access_token": token["access_token"]}
        if nonce is not None and (require_nonce or "nonce" in decoded.claims):
            params["nonce"] = nonce
        claims = CodeIDToken(
            decoded.claims, decoded.header,
            options={"iss": {"essential": True, "value": self.config.issuer},
                     "aud": {"essential": True, "value": self.config.client_id}},
            params=params,
        )
        claims.validate(leeway=self.config.leeway)
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise OAuthAuthenticationError("OIDC subject is invalid")
        if subject is not None and claims["sub"] != subject:
            raise OAuthAuthenticationError("OIDC refresh subject did not match")
        return claims["sub"]

    def current_access_token(self) -> str:
        """Return a bearer token; refresh under the vault lock, never log in."""
        try:
            with self.vault.locked():
                record = self._read()
                # Cached lookup does not require discovery or client secrets.
                cached = OAuth2Token(record["token"])
                if not cached.is_expired(leeway=self.config.leeway):
                    return cached["access_token"]
                if not record["token"].get("refresh_token"):
                    raise ReauthenticationRequired("OAuth credential requires explicit login")
                metadata = self._metadata()
                with self._session(metadata, token=record["token"]) as session:
                    token = session.refresh_token(metadata["token_endpoint"], allow_redirects=False)
                    self._validate_token(token)
                    if token.is_expired(leeway=self.config.leeway):
                        raise ReauthenticationRequired("OAuth credential requires explicit login")
                    if self.config.oidc and "id_token" in token:
                        # Refresh responses may omit nonce; if present it must
                        # match the original login nonce (OIDC Core 12.2).
                        self._validate_id_token(
                            token, metadata, nonce=record["oidc_nonce"],
                            subject=record["oidc_subject"], require_nonce=False)
                    record["token"] = dict(token)
                    self._write(record)
                    return token["access_token"]
        except CredentialError:
            raise
        except OAuthError as error:
            if error.error in {"invalid_grant", "invalid_token", "access_denied"}:
                raise ReauthenticationRequired("OAuth credential requires explicit login") from None
            raise OAuthAuthenticationError("Unable to resolve OAuth credential") from None
        except Exception:
            raise OAuthAuthenticationError("Unable to resolve OAuth credential") from None

    def login(self, *, authorization_handler: Callable[[str], str] | None = None,
              authorization_parameters: Mapping[str, str] | None = None,
              timeout: float = 180.0) -> None:
        """Explicitly authorize and persist tokens, returning no credential data.

        A trusted handler receives the authorization URL and returns the full
        callback URL. Without a handler, use a temporary loopback listener and
        the system browser. URLs/codes must never be printed or logged.
        """
        try:
            parameters = dict(authorization_parameters or {})
            if _RESERVED_PARAMETERS.intersection(parameters):
                raise OAuthAuthenticationError("OAuth authorization parameters override protected fields")
            metadata = self._metadata()
            if authorization_handler is None:
                with LoopbackRedirect(self.config.redirect_uri, timeout=timeout) as redirect:
                    self._login(metadata, redirect.uri, redirect.authorize, parameters)
            else:
                self._login(metadata, self.config.redirect_uri, authorization_handler, parameters)
        except CredentialError:
            raise
        except OAuthError as error:
            if error.error in {"invalid_grant", "access_denied"}:
                raise ReauthenticationRequired("OAuth login requires reauthorization") from None
            raise OAuthAuthenticationError("OAuth login failed") from None
        except Exception:
            raise OAuthAuthenticationError("OAuth login failed") from None

    def _login(self, metadata, redirect_uri, handler, parameters) -> None:
        verifier = generate_token(48) if self.config.pkce else None
        nonce = generate_token(32) if self.config.oidc else None
        with self._session(metadata, redirect_uri=redirect_uri) as session:
            if nonce:
                parameters["nonce"] = nonce
            url, state = session.create_authorization_url(
                metadata["authorization_endpoint"], code_verifier=verifier, **parameters)
            session.state = state
            response = handler(url)
            expected, actual = urlsplit(redirect_uri), urlsplit(response)
            if ((expected.scheme, expected.netloc, expected.path) !=
                    (actual.scheme, actual.netloc, actual.path) or actual.fragment):
                raise OAuthAuthenticationError("OAuth callback did not match redirect URI")
            with self.vault.locked():
                token = session.fetch_token(
                    metadata["token_endpoint"], authorization_response=response,
                    code_verifier=verifier, grant_type="authorization_code", allow_redirects=False)
                self._validate_token(token)
                if token.is_expired(leeway=self.config.leeway):
                    raise ReauthenticationRequired("OAuth login did not establish a usable token")
                record = {"token": dict(token)}
                if self.config.oidc:
                    record["oidc_subject"] = self._validate_id_token(token, metadata, nonce=nonce)
                    record["oidc_nonce"] = nonce
                self._write(record)
