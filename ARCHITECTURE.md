# credential-vault architecture

credential-vault is a small reusable Python package for encrypted credential persistence and OAuth/OIDC and Globus token lifecycle mechanics.

It is intentionally independent of applications which consume credentials.

## Dependency direction

```text
application/runtime
        |
        v
credential-vault
        |
        +-- keyring
        +-- keyrings.cryptfile
        +-- globus-sdk
        +-- Authlib / joserfc
        +-- requests
```

Consumers may depend on credential-vault. credential-vault must not import or depend on application packages.

`keyrings.cryptfile==1.5.0` selects the reviewed maintained fork version.
Package-source preparation mirrors its unchanged release wheel into a normal
Simple Index before pip runs; neither package installation nor Vault imports
download GitHub assets. The requirement alone does not bind an index or hash.
The source and artifact verification contract is documented in
`RELEASING.md` and `tools/cryptfile-source.json`; runtime code has no dependency
on mirroring tools or deployment orchestration.

## Responsibilities

credential-vault owns:

- one explicit encrypted vault built on a caller-selected path;
- a `MasterKeyProvider` contract;
- macOS Keychain as one master-key provider implementation;
- caller-injected master-key providers for other hosts;
- finite cooperative POSIX locking around vault access;
- opaque static-secret get/set/delete operations;
- a Globus SDK `TokenStorage` adapter backed by the encrypted vault;
- reusable Globus token lookup, SDK refresh persistence, and explicit login composition;
- Authlib-backed generic OAuth/OIDC authorization-code login and on-demand refresh;
- a temporary loopback callback listener for explicit desktop login;
- redacted storage/authentication errors.

The package does not own:

- provider, model, or inference configuration;
- application authorization or credential-selection policy;
- agent/persona/runtime behavior;
- network credential services;
- background token-refresh scheduling;
- application-specific filesystem locations;
- application-specific OAuth registrations, resources, scopes, or session policies.

## Vault model

The encrypted vault is the canonical credential-value store selected by its caller.

```text
trusted master-key source
        |
        v
keyrings.cryptfile
        |
        v
encrypted vault file
        |
        +-- opaque static secrets
        +-- serialized Globus SDK token records
        +-- generic OAuth token records and validated OIDC login context
```

The package never relies on Python's process-global keyring backend for composition. The master-key provider and encrypted backend are explicit objects.

On macOS, the package supplies a Keychain-backed master-key provider. The caller supplies the Keychain service/account names. Other hosts may inject another trusted `MasterKeyProvider` without changing the vault format.

## Locking

The first release targets POSIX hosts. Cooperating processes serialize vault operations through an adjacent finite advisory lock:

```text
<vault-path>.lock
```

The lock covers complete-file keyring operations and covers generic OAuth read, refresh, validation and replacement persistence,
and may be held across the same Globus SDK operations. Interactive browser
authorization happens before acquiring the lock; code exchange and persistence
happen under the lock.

This is cooperative process serialization. It does not claim crash-atomic persistence stronger than the selected `keyrings.cryptfile` backend provides.

## Globus lifecycle

The Globus integration preserves SDK ownership of OAuth behavior.

The package adapts the encrypted vault to the SDK `TokenStorage` contract and composes SDK apps/authorizers so a caller can request a current access token. If the access token requires refresh, `globus-sdk` performs the refresh and persists the replacement token data through the vault-backed storage.

Runtime token lookup never silently starts interactive login. Login is an explicit caller operation.

The package does not calculate OAuth expiration or implement refresh-token protocol behavior itself.

## Generic OAuth/OIDC lifecycle

`OAuthClientConfig` holds caller-selected public configuration. The caller supplies
an expected issuer for RFC 8414 / OIDC discovery, or direct HTTPS endpoints.
`OAuthTokenManager` composes Authlib's `OAuth2Session` for authorization code,
S256 PKCE, token endpoint authentication, expiry normalization and refresh.
Confidential clients obtain their secret from a caller-supplied callable at use
time; no client secret is placed in the configuration object or persisted here.

Public clients require PKCE. Confidential clients support Authlib's standard
`client_secret_basic` and `client_secret_post` methods and may disable PKCE when
required by their registration. Trusted callers may configure Authlib compliance
hooks for nonstandard envelopes. Hooks do not grant additional authority.

Login is explicit. A trusted caller handler can accept an authorization URL and
return the callback URL, or the package binds a temporary IPv4/IPv6 loopback
listener before opening the system browser. Authlib verifies state and exchanges
the code. The transport has finite waits, fixed browser responses, no request
logging and no long-running service. No codes/verifiers are returned or persisted.

Optional OIDC uses Authlib metadata and `CodeIDToken` validators and joserfc for
JWKS signature verification with a caller-selected asymmetric algorithm allowlist.
Issuer, audience, time, nonce and access-token hash checks remain library-owned.
The encrypted record retains the validated subject and original nonce to check
new refresh ID tokens. Refresh may omit a new ID token or its nonce; an included
nonce must match the login, and the subject must remain unchanged. Claims and raw
token records are not a public convenience API; identity mapping remains outside.
Metadata/JWKS use separate unauthenticated HTTPS transport without redirects or
implicit netrc credentials; token POSTs also prohibit redirects.

Generic records occupy the separate `credential-vault/oauth-tokens` keyring
service with caller-selected namespaces. They replace the full normalized token
response rather than merge stale fields. Authlib retains the existing refresh
token when the server omits a replacement and replaces it when one is supplied.
Cached lookups do not require discovery or a client secret. The caller must use
separate namespaces for different clients/accounts/issuers and must not reuse a
namespace after changing its authorization configuration without explicit login.

No vault format, master-key or locking migration is introduced. The existing
`beauty.post` contract remains unchanged: token state is created by explicit
caller-authorized login in an already initialized caller-owned vault. Deployment
must not discover vaults, authorize APIs or create credential state. Existing
Globus records and behavior are unchanged. An older installation simply does not
consume generic records; upgrade/reinstall/recovery preserves the encrypted file.
A crash/storage failure after a one-use refresh has been consumed can require
explicit login; no stronger crash atomicity or recovery guarantee is claimed.

## Security boundary

The vault protects stored credential values at rest when its master key is protected separately.

It does not hide credentials from a process authorized to open the vault, provide application authorization, provide a network isolation boundary, protect against a compromised process holding the master key, or control what a caller does with a returned credential.

## Package-owned deployment step

The distribution exposes one `beauty.post` entry point named
`credential-vault`, targeting `credential_vault.tools.post:main`. It is invoked
through the [common post contract](https://github.com/rpwagner/beauty-runtime/blob/main/docs/interface-contracts.md#installed-package-owned-post-script),
separately from installation, build and import, without a Maintainer dependency.
The current release has no package-owned state transition: empty owner intent
returns `unchanged` in either managed environment, including non-reconciling
copies, retries and recovery. Unsupported intent or invocation routing fails
with a fixed diagnostic before any state access.

The script does not import the credential APIs, discover caller vaults, open
keys/locks, validate credentials, or perform authentication/service actions.
Consumers retain all paths, identities and authority. The presence of this
transitive package and its script does not create an environment root or a
credential service. Future format/locking transitions require a separately
reviewed decision; none is implemented here.

## Supported runtime

The initial supported runtime is Python 3.14 on macOS and Linux/POSIX.

Windows support requires a separate locking design decision and is not part of the first release.
