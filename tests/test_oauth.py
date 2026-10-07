"""Offline protocol exercises using real Authlib and synthetic HTTP responses."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import multiprocessing
import socket
import threading
import time
import traceback
from dataclasses import replace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
import requests
from conftest import FakeMasterKeyProvider, fast_backend
from joserfc import jwt
from joserfc.jwk import RSAKey

from credential_vault import (
    CredentialNotFound, CredentialVault, OAuthAuthenticationError,
    OAuthClientConfig, OAuthTokenManager, ReauthenticationRequired, VaultUnavailable,
)
from credential_vault.oauth import _OAUTH_TOKEN_SERVICE

AUTH = "https://issuer.example/authorize"
TOKEN = "https://issuer.example/token"
ISSUER = "https://issuer.example"
METADATA = ISSUER + "/.well-known/openid-configuration"
JWKS = ISSUER + "/jwks"


def config(**kwargs):
    return replace(OAuthClientConfig(
        client_id="synthetic-client", scope="read", redirect_uri="http://127.0.0.1:8765/callback",
        authorization_endpoint=AUTH, token_endpoint=TOKEN), **kwargs)


def manager(vault, **kwargs):
    return OAuthTokenManager(config=config(), namespace="synthetic-account", vault=vault, **kwargs)


def token(**kwargs):
    return dict(access_token="synthetic-access", token_type="Bearer", expires_in=3600,
                refresh_token="synthetic-refresh", **kwargs)


def response(request, value, status=200):
    result = requests.Response()
    result.status_code = status
    result.headers["Content-Type"] = "application/json"
    result._content = json.dumps(value).encode()
    result.request = request
    result.url = request.url
    return result


@pytest.fixture
def transport(monkeypatch):
    calls, replies = [], []

    def send(session, request, **kwargs):
        calls.append((request, kwargs))
        assert replies, "Unexpected HTTP request"
        value = replies.pop(0)
        if isinstance(value, Exception):
            raise value
        if callable(value):
            value = value(request)
        return response(request, value)

    monkeypatch.setattr(requests.Session, "send", send)
    return calls, replies


def handler(url):
    query = parse_qs(urlsplit(url).query)
    return query["redirect_uri"][0] + "?" + urlencode({
        "code": "synthetic-code", "state": query["state"][0]})


def stored(vault, namespace="synthetic-account"):
    return json.loads(vault.get_password(_OAUTH_TOKEN_SERVICE, namespace))


def expire(vault):
    record = stored(vault)
    record["token"]["expires_at"] = 1
    vault.set_password(_OAUTH_TOKEN_SERVICE, "synthetic-account", json.dumps(record))


def test_pkce_exchange_cached_lookup_encryption_and_redaction(initialized_vault, transport, caplog):
    vault, _, path = initialized_vault
    calls, replies = transport
    replies.append(token())
    account = manager(vault)
    auth_query = {}

    def authorize(url):
        auth_query.update(parse_qs(urlsplit(url).query))
        return handler(url)

    with caplog.at_level(logging.DEBUG):
        assert account.login(authorization_handler=authorize) is None
        assert account.current_access_token() == "synthetic-access"
    assert len(calls) == 1
    request, options = calls[0]
    body = parse_qs(request.body)
    assert request.url == TOKEN
    assert body["grant_type"] == ["authorization_code"]
    assert body["code"] == ["synthetic-code"]
    assert body["client_id"] == ["synthetic-client"]
    verifier = body["code_verifier"][0]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert auth_query["code_challenge"] == [challenge]
    assert auth_query["code_challenge_method"] == ["S256"]
    assert request.headers.get("Authorization") is None
    assert options["allow_redirects"] is False
    assert options["timeout"] == 30
    assert stored(vault)["token"]["expires_at"] > time.time()
    for secret in ("synthetic-access", "synthetic-refresh", "synthetic-code", verifier):
        assert secret not in caplog.text
        assert secret.encode() not in path.read_bytes()
        assert secret not in repr(account)
        assert secret not in repr(account.config)


@pytest.mark.parametrize("auth_method", ["client_secret_basic", "client_secret_post"])
def test_confidential_exchange(initialized_vault, transport, auth_method):
    vault, _, _ = initialized_vault
    calls, replies = transport
    replies.append(token())
    secret = Mock(return_value="synthetic-client-secret")
    account = OAuthTokenManager(config(token_endpoint_auth_method=auth_method, pkce=False),
                               "synthetic-account", vault, client_secret_provider=secret)
    account.login(authorization_handler=handler)
    request = calls[0][0]
    body = parse_qs(request.body)
    assert "code_verifier" not in body
    if auth_method == "client_secret_basic":
        assert request.headers["Authorization"].startswith("Basic ")
        assert "client_secret" not in body
    else:
        assert body["client_secret"] == ["synthetic-client-secret"]
    secret.reset_mock()
    assert account.current_access_token() == "synthetic-access"
    secret.assert_not_called()
    assert "synthetic-client-secret" not in repr(account)


def test_refresh_replaces_rotating_pair_and_preserves_other_namespaces(initialized_vault, transport):
    vault, _, _ = initialized_vault
    calls, replies = transport
    account = manager(vault)
    replies.append(token())
    account.login(authorization_handler=handler)
    original = stored(vault)
    vault.set_password(_OAUTH_TOKEN_SERVICE, "other", json.dumps(original))
    expire(vault)
    replies.append({"access_token": "synthetic-new-access", "refresh_token": "synthetic-new-refresh",
                    "token_type": "bearer", "expires_in": 3600})
    assert account.current_access_token() == "synthetic-new-access"
    body = parse_qs(calls[1][0].body)
    assert body["refresh_token"] == ["synthetic-refresh"]
    assert body["grant_type"] == ["refresh_token"]
    assert stored(vault)["token"]["refresh_token"] == "synthetic-new-refresh"
    assert stored(vault, "other") == original
    assert account.current_access_token() == "synthetic-new-access"
    assert len(calls) == 2


def test_standard_refresh_without_replacement_retains_current_refresh(initialized_vault, transport):
    vault, _, _ = initialized_vault
    _, replies = transport
    account = manager(vault)
    replies.append(token())
    account.login(authorization_handler=handler)
    expire(vault)
    replies.append({"access_token": "synthetic-new-access", "token_type": "Bearer", "expires_in": 3600})
    assert account.current_access_token() == "synthetic-new-access"
    assert stored(vault)["token"]["refresh_token"] == "synthetic-refresh"


@pytest.mark.parametrize("error", ["invalid_grant", "invalid_token", "access_denied"])
def test_invalid_refresh_requires_login_without_disclosing_response(initialized_vault, transport, error):
    vault, _, _ = initialized_vault
    _, replies = transport
    account = manager(vault)
    replies.append(token())
    account.login(authorization_handler=handler)
    expire(vault)
    replies.append({"error": error, "error_description": "synthetic-refresh-leaked"})
    with pytest.raises(ReauthenticationRequired) as caught:
        account.current_access_token()
    assert "synthetic-refresh" not in "".join(traceback.format_exception(caught.value))


def test_missing_never_logs_in_or_uses_transport(initialized_vault, transport):
    vault, _, _ = initialized_vault
    with pytest.raises(CredentialNotFound):
        manager(vault).current_access_token()
    assert transport[0] == []


def test_expired_unrefreshable_and_non_expiring_token(initialized_vault, transport):
    vault, _, _ = initialized_vault
    _, replies = transport
    account = manager(vault)
    replies.append({"access_token": "synthetic-access", "token_type": "Bearer"})
    account.login(authorization_handler=handler)
    assert account.current_access_token() == "synthetic-access"
    expire(vault)
    with pytest.raises(ReauthenticationRequired):
        account.current_access_token()


@pytest.mark.parametrize("value", [
    "synthetic-non-json", "[]", "{}", json.dumps({"token": {"access_token": "synthetic-access"}}),
    json.dumps({"token": {"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": 3600}}),
    json.dumps({"token": {"access_token": "synthetic-access", "token_type": "Bearer", "expires_at": "nan"}}),
    json.dumps({"token": {"access_token": "synthetic-access", "token_type": "Bearer", "expires_at": True}}),
])
def test_malformed_storage_redacted(initialized_vault, value, transport):
    vault, _, _ = initialized_vault
    vault.set_password(_OAUTH_TOKEN_SERVICE, "synthetic-account", value)
    with pytest.raises(VaultUnavailable) as caught:
        manager(vault).current_access_token()
    assert "synthetic" not in "".join(traceback.format_exception(caught.value))
    assert transport[0] == []


@pytest.mark.parametrize("reply", [
    {"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": 0},
    {"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": -1},
    {"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": "nan"},
    {"token_type": "Bearer"}, {"access_token": "synthetic-access", "token_type": "MAC"},
])
def test_failed_login_preserves_existing_token(initialized_vault, transport, reply):
    vault, _, _ = initialized_vault
    _, replies = transport
    account = manager(vault)
    replies.append(token())
    account.login(authorization_handler=handler)
    before = stored(vault)
    replies.append(reply)
    with pytest.raises((OAuthAuthenticationError, ReauthenticationRequired)):
        account.login(authorization_handler=handler)
    assert stored(vault) == before


@pytest.mark.parametrize("reply", [
    requests.ConnectionError("synthetic-secret-error"),
    {"error": "server_error", "error_description": "synthetic-secret-error"},
])
def test_dependency_errors_are_redacted(initialized_vault, transport, reply):
    vault, _, _ = initialized_vault
    transport[1].append(reply)
    with pytest.raises(OAuthAuthenticationError) as caught:
        manager(vault).login(authorization_handler=handler)
    assert "synthetic-secret" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("callback", [
    "http://127.0.0.1:8765/callback?code=synthetic-code&state=wrong",
    "http://evil.example/callback?code=synthetic-code",
    "http://127.0.0.1:8765/other?code=synthetic-code",
])
def test_callback_checks_before_token_exchange(initialized_vault, transport, callback):
    vault, _, _ = initialized_vault
    with pytest.raises(OAuthAuthenticationError):
        manager(vault).login(authorization_handler=lambda url: callback)
    assert transport[0] == []


@pytest.mark.parametrize("provider,reply", [
    ("gitlab", {"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": 7200,
                "refresh_token": "synthetic-refresh", "created_at": 123}),
    ("github", {"access_token": "synthetic-access", "token_type": "bearer", "expires_in": 28800,
                "refresh_token": "synthetic-refresh", "refresh_token_expires_in": 15897600}),
    ("atlassian", {"access_token": "synthetic-access", "token_type": "Bearer", "expires_in": 3600,
                   "refresh_token": "synthetic-refresh", "scope": "offline_access read"}),
    ("box", {"access_token": "synthetic-access", "token_type": "bearer", "expires_in": 3600,
             "refresh_token": "synthetic-refresh", "restricted_to": []}),
    ("slack", {"ok": True, "authed_user": {"access_token": "synthetic-access", "token_type": "user",
              "expires_in": 43200, "refresh_token": "synthetic-refresh", "scope": "canvases:read"}}),
])
def test_representative_shapes_use_same_lifecycle(initialized_vault, transport, provider, reply):
    vault, _, _ = initialized_vault
    _, replies = transport

    def configure(session):
        # A caller-owned Authlib compliance hook handles a nonstandard envelope.
        # The package itself has no Slack/provider token-manager subclass.
        if provider == "slack":
            def normalize(result):
                value = dict(result.json()["authed_user"])
                value["token_type"] = "Bearer"
                result._content = json.dumps(value).encode()
                return result
            session.register_compliance_hook("access_token_response", normalize)
            session.register_compliance_hook("refresh_token_response", normalize)

    account = manager(vault, configure_session=configure)
    replies.append(reply)
    account.login(authorization_handler=handler)
    expire(vault)
    replies.append(reply)
    assert account.current_access_token() == "synthetic-access"
    assert stored(vault)["token"]["refresh_token"] == "synthetic-refresh"


def oidc_metadata():
    return {"issuer": ISSUER, "authorization_endpoint": AUTH, "token_endpoint": TOKEN,
            "jwks_uri": JWKS, "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "subject_types_supported": ["public"]}


def test_discovery_and_oidc_validation(initialized_vault, transport):
    vault, _, _ = initialized_vault
    calls, replies = transport
    key = RSAKey.generate_key(2048)
    nonce = []
    account = OAuthTokenManager(config(authorization_endpoint=None, token_endpoint=None,
        metadata_url=METADATA, issuer=ISSUER, oidc=True, scope="openid read"),
        "synthetic-account", vault)
    replies.append(oidc_metadata())

    def signed(request):
        value = token()
        value["id_token"] = jwt.encode({"alg": "RS256"}, {
            "iss": ISSUER, "aud": "synthetic-client", "sub": "synthetic-subject",
            "iat": int(time.time()), "exp": int(time.time()) + 3600, "nonce": nonce[0]}, key)
        return value

    replies.extend([signed, {"keys": [key.as_dict(private=False)]}])

    def authorize(url):
        nonce.append(parse_qs(urlsplit(url).query)["nonce"][0])
        return handler(url)

    account.login(authorization_handler=authorize)
    assert account.current_access_token() == "synthetic-access"
    assert [call[0].url for call in calls] == [METADATA, TOKEN, JWKS]
    assert calls[0][0].headers.get("Authorization") is None
    assert calls[2][0].headers.get("Authorization") is None
    assert stored(vault)["oidc_subject"] == "synthetic-subject"
    # Refresh without a new ID token is valid and does not reuse the old JWT.
    expire(vault)
    replies.extend([oidc_metadata(), token()])
    assert account.current_access_token() == "synthetic-access"
    assert "id_token" not in stored(vault)["token"]


@pytest.mark.parametrize("bad_claim", ["iss", "aud", "nonce", "exp", "signature", "algorithm"])
def test_oidc_invalid_claim_or_signature_not_persisted(initialized_vault, transport, bad_claim):
    vault, _, _ = initialized_vault
    _, replies = transport
    key = RSAKey.generate_key(2048)
    nonce = []
    account = OAuthTokenManager(config(issuer=ISSUER, jwks_uri=JWKS,
                                      oidc=True, scope="openid"), "synthetic-account", vault)

    def signed(request):
        claims = {"iss": ISSUER, "aud": "synthetic-client", "sub": "synthetic-subject",
                  "iat": int(time.time()), "exp": int(time.time()) + 3600, "nonce": nonce[0]}
        if bad_claim in {"iss", "aud", "nonce"}:
            claims[bad_claim] = "synthetic-wrong"
        if bad_claim == "exp":
            claims["exp"] = 1
        signing_key = RSAKey.generate_key(2048) if bad_claim == "signature" else key
        return token(id_token=jwt.encode({"alg": "RS512" if bad_claim == "algorithm" else "RS256"},
                                         claims, signing_key))

    replies.extend([signed, {"keys": [key.as_dict(private=False)]}])

    def authorize(url):
        nonce.append(parse_qs(urlsplit(url).query)["nonce"][0])
        return handler(url)

    with pytest.raises(OAuthAuthenticationError):
        account.login(authorization_handler=authorize)
    assert vault.get_password(_OAUTH_TOKEN_SERVICE, "synthetic-account") is None


def test_rfc8414_metadata_and_issuer_mismatch(initialized_vault, transport):
    vault, _, _ = initialized_vault
    _, replies = transport
    account = OAuthTokenManager(config(authorization_endpoint=None, token_endpoint=None,
                                      metadata_url=METADATA, issuer=ISSUER), "synthetic-account", vault)
    replies.extend([oidc_metadata(), token()])
    account.login(authorization_handler=handler)
    before = stored(vault)
    replies.append(dict(oidc_metadata(), issuer="https://other.example"))
    with pytest.raises(OAuthAuthenticationError):
        account.login(authorization_handler=handler)
    assert stored(vault) == before


def _refresh_worker(path, key, start, count, results):
    vault = CredentialVault.open(path, master_key_provider=FakeMasterKeyProvider(key),
                                 backend_factory=fast_backend)

    def send(session, request, **kwargs):
        with count.get_lock():
            count.value += 1
        time.sleep(0.1)
        return response(request, {"access_token": "synthetic-new-access", "token_type": "Bearer",
                                  "refresh_token": "synthetic-new-refresh", "expires_in": 3600})

    requests.Session.send = send
    start.wait(5)
    results.put(manager(vault).current_access_token())


def test_concurrent_refresh_consumes_single_use_token_once(initialized_vault, transport):
    vault, provider, path = initialized_vault
    transport[1].append(token())
    manager(vault).login(authorization_handler=handler)
    expire(vault)
    context = multiprocessing.get_context("fork")
    start, count, results = context.Event(), context.Value("i", 0), context.Queue()
    processes = [context.Process(target=_refresh_worker, args=(path, provider.key, start, count, results))
                 for _ in range(2)]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join()
        assert process.exitcode == 0
    assert count.value == 1
    assert [results.get(timeout=1) for _ in processes] == ["synthetic-new-access"] * 2
    assert stored(vault)["token"]["refresh_token"] == "synthetic-new-refresh"


@pytest.mark.parametrize("kwargs", [
    {"pkce": False}, {"token_endpoint": "http://issuer.example/token"},
    {"token_endpoint": "https://synthetic-secret@issuer.example/token"},
    {"metadata_url": METADATA}, {"redirect_uri": "http://remote.example/callback"},
    {"oidc": True}, {"id_token_algorithms": ("none",)},
    {"timeout": float("nan")}, {"leeway": -1},
])
def test_invalid_config_redacted(kwargs):
    with pytest.raises(ValueError) as caught:
        config(**kwargs)
    assert "synthetic-secret" not in str(caught.value)


def test_default_login_combines_loopback_with_authlib(initialized_vault, transport, monkeypatch):
    vault, _, _ = initialized_vault
    calls, replies = transport
    replies.append(token())
    workers = []

    def open_browser(url):
        callback = urlsplit(handler(url))

        def deliver():
            with socket.create_connection((callback.hostname, callback.port), timeout=2) as connection:
                connection.sendall((f"GET {callback.path}?{callback.query} HTTP/1.1\r\n"
                                    f"Host: {callback.netloc}\r\nConnection: close\r\n\r\n").encode())
                while connection.recv(4096):
                    pass
        worker = threading.Thread(target=deliver)
        worker.start()
        workers.append(worker)
        return True

    monkeypatch.setattr("credential_vault.loopback.webbrowser.open", open_browser)
    account = OAuthTokenManager(config(redirect_uri="http://127.0.0.1:0/callback"),
                               "synthetic-account", vault)
    account.login(timeout=2)
    for worker in workers:
        worker.join(2)
        assert not worker.is_alive()
    assert account.current_access_token() == "synthetic-access"
    assert ":0/" not in parse_qs(calls[0][0].body)["redirect_uri"][0]


@pytest.mark.parametrize("change", ["valid", "omit_nonce", "wrong_nonce", "wrong_subject"])
def test_refresh_id_token_validates_original_login_context(initialized_vault, transport, change):
    vault, _, _ = initialized_vault
    _, replies = transport
    key = RSAKey.generate_key(2048)
    nonce = []
    account = OAuthTokenManager(config(issuer=ISSUER, jwks_uri=JWKS,
                                      oidc=True, scope="openid"), "synthetic-account", vault)

    def signed(request):
        refreshing = parse_qs(request.body)["grant_type"] == ["refresh_token"]
        claims = {"iss": ISSUER, "aud": "synthetic-client", "sub": "synthetic-subject",
                  "iat": int(time.time()), "exp": int(time.time()) + 3600, "nonce": nonce[0]}
        if refreshing:
            if change == "omit_nonce":
                del claims["nonce"]
            elif change == "wrong_nonce":
                claims["nonce"] = "synthetic-wrong"
            elif change == "wrong_subject":
                claims["sub"] = "synthetic-other-subject"
        return token(id_token=jwt.encode({"alg": "RS256"}, claims, key))

    def authorize(url):
        nonce.append(parse_qs(urlsplit(url).query)["nonce"][0])
        return handler(url)

    jwks = {"keys": [key.as_dict(private=False)]}
    replies.extend([signed, jwks])
    account.login(authorization_handler=authorize)
    expire(vault)
    original = stored(vault)
    replies.extend([signed, jwks])
    if change in {"valid", "omit_nonce"}:
        assert account.current_access_token() == "synthetic-access"
    else:
        with pytest.raises(OAuthAuthenticationError):
            account.current_access_token()
        assert stored(vault) == original


def test_refresh_storage_failure_never_returns_unpersisted_token(initialized_vault, transport, monkeypatch):
    vault, _, _ = initialized_vault
    _, replies = transport
    account = manager(vault)
    replies.append(token())
    account.login(authorization_handler=handler)
    expire(vault)
    replies.append(token())

    def fail(*args):
        raise VaultUnavailable("Unable to write credential vault")

    monkeypatch.setattr(vault, "_set_password_unlocked", fail)
    with pytest.raises(VaultUnavailable):
        account.current_access_token()


@pytest.mark.parametrize("field", ["state", "nonce", "redirect_uri", "code_verifier", "scope"])
def test_authorization_parameters_cannot_override_protocol_fields(initialized_vault, transport, field):
    vault, _, _ = initialized_vault
    with pytest.raises(OAuthAuthenticationError):
        manager(vault).login(authorization_handler=handler,
                             authorization_parameters={field: "synthetic-value"})
    assert transport[0] == []
