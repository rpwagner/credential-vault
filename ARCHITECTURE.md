# credential-vault architecture

credential-vault is a small reusable Python package for encrypted credential persistence and Globus token lifecycle mechanics.

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
```

Consumers may depend on credential-vault. credential-vault must not import or depend on application packages.

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
```

The package never relies on Python's process-global keyring backend for composition. The master-key provider and encrypted backend are explicit objects.

On macOS, the package supplies a Keychain-backed master-key provider. The caller supplies the Keychain service/account names. Other hosts may inject another trusted `MasterKeyProvider` without changing the vault format.

## Locking

The first release targets POSIX hosts. Cooperating processes serialize vault operations through an adjacent finite advisory lock:

```text
<vault-path>.lock
```

The lock covers complete-file keyring operations and may be held across Globus SDK read, validation, refresh, and persistence.

This is cooperative process serialization. It does not claim crash-atomic persistence stronger than the selected `keyrings.cryptfile` backend provides.

## Globus lifecycle

The Globus integration preserves SDK ownership of OAuth behavior.

The package adapts the encrypted vault to the SDK `TokenStorage` contract and composes SDK apps/authorizers so a caller can request a current access token. If the access token requires refresh, `globus-sdk` performs the refresh and persists the replacement token data through the vault-backed storage.

Runtime token lookup never silently starts interactive login. Login is an explicit caller operation.

The package does not calculate OAuth expiration or implement refresh-token protocol behavior itself.

## Security boundary

The vault protects stored credential values at rest when its master key is protected separately.

It does not hide credentials from a process authorized to open the vault, provide application authorization, provide a network isolation boundary, protect against a compromised process holding the master key, or control what a caller does with a returned credential.

## Supported runtime

The initial supported runtime is Python 3.13 and 3.14 on macOS and Linux/POSIX.

Windows support requires a separate locking design decision and is not part of the first release.
