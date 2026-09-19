"""Portable encrypted credential storage and Globus token lifecycle."""

from .errors import (
    CredentialError,
    CredentialNotFound,
    GlobusAuthenticationError,
    ReauthenticationRequired,
    UnsupportedPlatformError,
    VaultLockTimeout,
    VaultUnavailable,
)
from .globus import GlobusTokenManager, VaultTokenStorage
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
    "ReauthenticationRequired",
    "UnsupportedPlatformError",
    "VaultLockTimeout",
    "VaultStatus",
    "VaultTokenStorage",
    "VaultUnavailable",
)
