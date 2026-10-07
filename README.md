# credential-vault

Small standalone Python package for portable encrypted credential storage and reusable OAuth/OIDC and Globus token lifecycle behavior.

The package is intentionally application-neutral. Consumers choose vault paths, master-key identities, credential names, OAuth/Globus clients, endpoints, resources, scopes, and session policy. It has no dependency on an inference or application runtime.

## Security boundary

`CredentialVault` uses an explicit `keyrings.cryptfile` backend to protect credential values at rest. A separately protected master key unlocks that file. One adjacent POSIX advisory lock serializes cooperating readers and writers, including complete OAuth/Globus read, validation, library refresh, and persistence operations.

The package does not provide application authorization, a credential broker, a network boundary, or protection from a process which already holds the master key. It cannot control a secret after returning it to a caller. The lock is cooperative and does not claim stronger crash atomicity than `keyrings.cryptfile` provides.

## Encrypted vault

Callers always supply the vault path and master-key provider. Initialization is non-destructive: an existing vault without its master key fails instead of generating a replacement.

```python
from credential_vault import CredentialVault

vault = CredentialVault.initialize(
    path="/caller/selected/credentials.cryptfile",
    master_key_provider=provider,
)
vault.set_password("service", "account", "opaque-value")
value = vault.get_password("service", "account")
vault.delete_password("service", "account")
```

`get_password()` returns `None` for a missing value. Storage and locking failures raise package-defined errors with dependency details removed.

### Master-key providers

Any host can inject the small `MasterKeyProvider` protocol:

```python
class MasterKeyProvider:
    def get_key(self) -> str | None: ...
    def set_key(self, value: str) -> None: ...
    def delete_key(self) -> None: ...
```

On macOS, the included provider stores only the master secret in a caller-named Keychain item. It explicitly instantiates the macOS backend and does not change Python's process-global keyring:

```python
from credential_vault import MacOSKeychainMasterKeyProvider

provider = MacOSKeychainMasterKeyProvider(
    service="caller-chosen-service",
    account="caller-chosen-account",
)
```

Linux and other POSIX callers inject their selected trusted master-key provider. This package intentionally does not select a host secret-storage policy for them.

## Globus tokens

`VaultTokenStorage` implements the Globus SDK `TokenStorage` contract and serializes the SDK's own `TokenStorageData`; it does not define another token schema.

```python
from credential_vault import GlobusTokenManager, VaultTokenStorage

storage = VaultTokenStorage("caller-namespace", vault=vault)

tokens = GlobusTokenManager(
    app_name="caller app",
    native_client_id="caller-native-client-id",
    resource_server="caller-resource-server",
    scopes=("caller-scope",),
    namespace="caller-namespace",
    vault=vault,
)

access_token = tokens.current_access_token()
```

`current_access_token()` never starts interactive login. It asks the Globus SDK for an authorizer, allowing the SDK to validate, refresh, and persist replacement token data while the vault lock is held. A missing record raises `CredentialNotFound`; unusable authorization raises `ReauthenticationRequired`.

Login is a separate, explicit operation:

```python
from globus_sdk.gare import GlobusAuthorizationParameters

tokens.login(
    authorization_parameters=GlobusAuthorizationParameters(
        session_required_mfa=True,
    )
)
```

The SDK owns the interactive flow and persists tokens only after successful login. Callers can also supply a Globus login-flow manager, redirect URI, and authorization parameters when constructing `GlobusTokenManager`.

No scheduler or daemon is required for correctness. A future scheduled consumer can call the same `current_access_token()` method to refresh the canonical vault proactively; on-demand callers retain the same refresh capability.

## Generic OAuth 2.0 / OIDC user tokens

Authlib owns authorization code, PKCE, expiration and refresh. The package adds
explicit login composition and encrypted persistence under the existing vault
lock. It supports direct HTTPS endpoints and RFC 8414 / OIDC discovery, public
clients with S256 PKCE, confidential clients, and optional OIDC validation.

```python
from credential_vault import OAuthClientConfig, OAuthTokenManager

config = OAuthClientConfig(
    client_id="caller-client-id",
    redirect_uri="http://127.0.0.1:8765/callback",
    scope="caller-scope",
    authorization_endpoint="https://api.example/authorize",
    token_endpoint="https://api.example/token",
)
tokens = OAuthTokenManager(config, namespace="caller-client-account", vault=vault)
tokens.login()  # Explicit system-browser login; temporary localhost callback.
access_token = tokens.current_access_token()  # Never opens a browser.
```

Supply the redirect URI registered with your authorization server. An explicitly
configured port `0` binds an available local port when the server permits dynamic
loopback ports; fixed ports work for registrations which require an exact URI.
`localhost`, `127.0.0.1`, and `::1` are supported. `login(timeout=180)` bounds the
callback wait. For a caller-managed HTTPS callback, provide
`login(authorization_handler=handler)`; the trusted handler receives an
in-memory authorization URL and returns the full callback URL. Never print/log
these URLs or authorization codes. `login()` returns `None` after persistence.

For confidential clients set `token_endpoint_auth_method="client_secret_basic"`
or `"client_secret_post"` and supply `client_secret_provider` to the manager.
This callable retrieves the secret from your trusted storage when needed;
configuration files and command arguments must never contain the secret.
PKCE defaults to S256; only confidential clients may select `pkce=False`.

For discovery replace the two direct endpoints with `metadata_url` and the
explicit expected `issuer`. Enable `oidc=True`, include `openid` in `scope`, and
select `id_token_algorithms` (default `("RS256",)`) for ID-token validation.
Direct OIDC configuration instead supplies `issuer` and `jwks_uri`. The library
validates signatures and claims; no user mapping or authorization is performed.
JWKS are fetched afresh when validating a new ID token, including refresh.

`configure_session` is a trusted callable receiving each Authlib session. It can
register maintained-library compliance hooks for a nonstandard token envelope
(for example, selecting a nested user-token response). Keep those hooks in the
caller; there are no provider-specific managers. `authorization_parameters` on
`login()` accepts additional authorization fields such as `prompt` or
`user_scope`, while protecting state, nonce, client, scope and PKCE fields.
Do not use hooks to log tokens, weaken TLS or change client authority.

Refresh holds the lock through read, refresh and replacement persistence, so
cooperating processes cannot consume the same rotating token concurrently.
Tokens without provider expiry remain usable until the provider rejects them;
this API does not introspect or call resource APIs. Missing tokens raise
`CredentialNotFound`; expired tokens without refresh or rejected refresh grants
raise `ReauthenticationRequired`; other protocol errors raise the redacted
`OAuthAuthenticationError`, and malformed stored records raise `VaultUnavailable`.
A storage failure after consuming a one-use refresh may require explicit login.
Use a unique namespace per client/account/issuer; changing its configuration
requires explicit login. Raw stored token records and ID claims are not exposed.

Globus continues to use `globus-sdk`. No scheduler, broker, consumer integration,
vault migration, or automatic login is introduced by generic token support.

## Platform support

Python 3.14 is supported on macOS and Linux/other POSIX hosts. Vault operations fail clearly on Windows because this release requires POSIX `fcntl` locking.

## Development

Read `AGENTS.md` and `ARCHITECTURE.md` before changing the repository.

### Package sources

The dependency is the maintained `rpwagner/keyrings.cryptfile` **1.5.0** wheel,
unchanged from its reviewed release. It is expressed as an ordinary package
requirement; pip does not download a GitHub release URL from Vault metadata.
The source must be prepared before installation. See
[the package-source procedure](RELEASING.md#reviewed-cryptfile-package-source)
for mirroring, the reviewed artifact identity, and pip's multiple-index limitation.
An unrestricted PyPI extra index is not a fork identity guarantee.

After preparing those sources, normal validation is:

```bash
python -m pip install -e ".[test]"
python -m pytest
python -m pip check
git diff --check
```

## Releases

Installable releases use the immutable wheel and source-distribution artifacts attached to an annotated `v<version>` GitHub Release. Tagged releases are built and published only after explicit approval through the protected `release` environment. See `RELEASING.md`.
