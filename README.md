# credential-vault

Small standalone Python package for portable encrypted credential storage and reusable Globus token lifecycle behavior.

The package is intentionally application-neutral. Consumers choose vault paths, master-key identities, credential names, Globus clients/resources/scopes, and authorization policy.

The first implementation is tracked in [issue #1](https://github.com/rpwagner/credential-vault/issues/1).

## Development

Read `AGENTS.md` and `ARCHITECTURE.md` before changing the repository.

Normal validation:

```bash
python -m pip install -e ".[test]"
python -m pytest
python -m pip check
git diff --check
```

The initial supported runtime is Python 3.13 and 3.14 on macOS and Linux/POSIX.

## Releases

Tagged releases are built and published as GitHub Release artifacts after explicit approval through the protected `release` environment. See `RELEASING.md`.
