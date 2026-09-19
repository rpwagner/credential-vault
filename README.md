# credential-vault

Small standalone Python package for portable encrypted credential storage and reusable Globus token lifecycle behavior.

The package is intentionally application-neutral. Consumers choose vault paths, master-key identities, credential names, Globus clients, resources, scopes, and session policy. It has no dependency on an inference or application runtime.

## Security boundary

`CredentialVault` uses an explicit `keyrings.cryptfile` backend to protect credential values at rest. A separately protected master key unlocks that file. One adjacent POSIX advisory lock serializes cooperating readers and writers, including a complete Globus read, validation, SDK refresh, and persistence operation.

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

## Platform support

Python 3.13 and 3.14 are supported on macOS and Linux/other POSIX hosts. Vault operations fail clearly on Windows because this release requires POSIX `fcntl` locking.

## Development

Read `AGENTS.md` and `ARCHITECTURE.md` before changing the repository.

Normal validation:

```bash
python -m pip install -e ".[test]"
python -m pytest
python -m pip check
git diff --check
```

## Releases

Installable releases use the immutable wheel and source-distribution artifacts attached to an annotated `v<version>` GitHub Release. Tagged releases are built and published only after explicit approval through the protected `release` environment. See `RELEASING.md`.
