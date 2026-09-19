def test_package_imports() -> None:
    import credential_vault

    assert credential_vault.__name__ == "credential_vault"
    assert credential_vault.__all__ == (
        "CredentialError",
        "CredentialNotFound",
        "CredentialVault",
        "GlobusAuthenticationError",
        "GlobusTokenManager",
        "MacOSKeychainMasterKeyProvider",
        "MasterKeyProvider",
        "ReauthenticationRequired",
        "UnsupportedPlatformError",
        "VaultLockTimeout",
        "VaultStatus",
        "VaultTokenStorage",
        "VaultUnavailable",
    )
