# Releasing credential-vault

For coupled Beauty-system work, apply the [canonical policy](https://github.com/rpwagner/beauty-runtime/blob/main/AGENTS.md)
for development/evaluation release stages, evidence, and upgrade consequences.
The procedures and protected publication approval here remain operational.
Pending tagged/deployed evaluation is recorded separately from pre-merge tests.

Releases start through **Actions -> Release -> Run workflow** on `main` with `version: X.Y.Z`. The workflow commits only the package version in `pyproject.toml`, validates that commit, and publishes after approval in the protected `release` environment. Publication is to GitHub Releases, not PyPI.

## One-time repository setup

Keep the `release` environment and its required reviewer, administrator-bypass restriction, and deployment branch restriction that permits `main`. A manual `workflow_dispatch` runs from `main`, so a `v*`-only tag restriction would block the approval job. Existing tag restrictions may remain for other workflows; add `main` to the allowed deployments for this environment. If the person initiating a release also approves it, leave **Prevent self-review** disabled; enable it when a separate reviewer is available. These settings live in GitHub, outside workflow YAML.

The Release job needs permission to push its version-only commit to `main`. If a protection rule rejects that push, allow only the Release workflow identity a narrow `main` update exception. Do not force-push or place the release commit only on a temporary branch.

## Publishing a release

1. Merge reviewed feature and fix changes to `main` and confirm its normal push CI is green.
2. Open **Actions -> Release -> Run workflow**, select `main`, and enter `version: X.Y.Z`.
3. The workflow validates the PEP 440 version and starting CI, commits `chore: release vX.Y.Z [skip ci]` on `main`, runs Linux and macOS Python 3.14 tests, builds and smoke-tests the wheel and sdist, and generates `SHA256SUMS`.
4. Approve the pending `release` environment deployment. After validation and approval the workflow makes an immutable annotated tag on the exact release commit and creates or repairs the GitHub Release with the validated assets.

The version-only commit skips redundant normal CI because the release workflow validates its exact SHA. If a run fails after the commit, rerun with the same version while that commit remains current `main`; the workflow reuses it. If `main` moves, the retry stops. An existing tag is accepted only if it points to that same commit and is never moved.

Do not dispatch a release until publication is explicitly authorized.

## Exact-source coordinated publication

The existing manual release workflows optionally accept `expected_sha`.
When supplied, it must be a full lowercase 40-character main commit SHA matching
the dispatch's `GITHUB_SHA`; a mismatch stops before checkout or any version
commit/publication. Omit it to retain the current manual release procedure.
Existing CI checks, review/environment gates, version-only commits, immutable
tags and non-force main updates remain in place. This input grants no release
or deployment approval and adds no runtime/package dependency.

[Beauty-system release-set preparation](https://github.com/rpwagner/beauty-runtime/issues/281)
supplies this guard only after explicit approval of an exact set; orchestration
is owned outside this repository. Publication remains in these existing workflows.

## Upgrade and recovery handoff

The wheel and source distribution include `credential_vault/tools/post.py`.
The [common installed post contract](https://github.com/rpwagner/beauty-runtime/blob/main/docs/interface-contracts.md#installed-package-owned-post-script)
owns discovery, bounded JSON context/results and invocation with the intended
environment's Python (`-I -B`), outside a checkout. Deployment coordinates this
explicit step after package installation; pip, builds and imports do not run it.

For this release there is **no migration**. With empty owner intent the step
reports successful `unchanged` without requiring a vault or master key. Install,
upgrade, downgrade, reinstall, retry and explicitly authorized recovery use
the same no-op. Unsupported owner intent fails without touching state; it does
not request initialization, replacement, rotation or token refresh. This says
nothing about reversing state changes made by other releases or consumers.

CI and release packaging smoke-test both clean wheel and sdist installations,
including RECORD-bound discovery and repeated installed invocation:

```bash
/absolute/clean-environment/bin/python -I -B tools/check_installed_post.py
```

The checker runs the installed script in a disposable directory and verifies no
state creation. Offline safety tests additionally forbid credential imports,
filesystem access, locking, subprocesses and network calls during post execution.
Supported-host integration with Maintainer remains separate evaluation evidence.
Releases predating this script retain the recovery procedure below; absence of
a script in an old artifact must not be reported as a successful post step.

For a change with upgrade consequences, record package/platform compatibility,
caller configuration, vault/master-key and locking implications, migration,
consumer activation, regression evidence, and recovery in its issue/PR. Identify
the owning consumer or deployment mechanism and any transition it cannot yet
express; this document does not introduce coordinated deployment or signaling.

Recovery requires the prior known-good tagged artifact and compatible
caller-selected configuration, vault state, and master-key access. Installing an
older wheel alone cannot reverse an incompatible stored-format or credential
change. Credential rotation and migration need their own reviewed authorization;
never overwrite a real vault to obtain validation evidence.
