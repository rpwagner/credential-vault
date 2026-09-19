"""Redacted public errors for credential-vault operations."""


class CredentialError(Exception):
    """Base class for failures at the credential-vault boundary."""


class CredentialNotFound(CredentialError):
    """A requested secret or token record is absent."""


class VaultUnavailable(CredentialError):
    """The selected encrypted vault cannot be initialized or opened."""


class VaultLockTimeout(VaultUnavailable):
    """The finite wait for the cooperative vault lock expired."""


class UnsupportedPlatformError(VaultUnavailable):
    """The requested storage operation is unsupported on this platform."""


class ReauthenticationRequired(CredentialError):
    """Stored Globus authorization can no longer produce a usable token."""


class GlobusAuthenticationError(CredentialError):
    """Globus authentication failed without exposing dependency details."""
