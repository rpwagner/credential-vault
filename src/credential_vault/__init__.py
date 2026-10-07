"""Portable encrypted credential storage and OAuth/OIDC and Globus token lifecycles."""

from .errors import (
    CredentialError,
    CredentialNotFound,
    GlobusAuthenticationError,
    OAuthAuthenticationError,
    ReauthenticationRequired,
    UnsupportedPlatformError,
    VaultLockTimeout,
    VaultUnavailable,
)
from .globus import GlobusTokenManager, VaultTokenStorage
from .oauth import OAuthClientConfig, OAuthTokenManager
from .master_keys import MacOSKeychainMasterKeyProvider, MasterKeyProvider
from .vault import CredentialVault, VaultStatus

__all__ = (
    "CredentialError",
    "CredentialNotFound",
    "CredentialVault",
    "GlobusAuthenticationError",
    "GlobusTokenManager",
    "MacOSKeychainMasterKeyProvider",
    "MasterKeyProvider",
    "OAuthAuthenticationError",
    "OAuthClientConfig",
    "OAuthTokenManager",
    "ReauthenticationRequired",
    "UnsupportedPlatformError",
    "VaultLockTimeout",
    "VaultStatus",
    "VaultTokenStorage",
    "VaultUnavailable",
)
