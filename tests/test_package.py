from importlib.metadata import distribution

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


def test_installed_distribution_exposes_post_entry_point() -> None:
    dist = distribution("credential-vault")
    posts = [entry for entry in dist.entry_points if entry.group == "beauty.post"]
    assert [(entry.name, entry.value) for entry in posts] == [
        ("credential-vault", "credential_vault.tools.post:main")
    ]
