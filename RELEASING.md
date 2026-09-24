# Releasing credential-vault

Releases start through **Actions -> Release -> Run workflow** on `main` with `version: X.Y.Z`. The workflow commits only the package version in `pyproject.toml`, validates that commit, and publishes after approval in the protected `release` environment. Publication is to GitHub Releases, not PyPI.

## One-time repository setup

Keep the `release` environment and its required reviewer, administrator-bypass restriction, and deployment branch restriction that permits `main`. A manual `workflow_dispatch` runs from `main`, so a `v*`-only tag restriction would block the approval job. Existing tag restrictions may remain for other workflows; add `main` to the allowed deployments for this environment. If the person initiating a release also approves it, leave **Prevent self-review** disabled; enable it when a separate reviewer is available. These settings live in GitHub, outside workflow YAML.

The Release job needs permission to push its version-only commit to `main`. If a protection rule rejects that push, allow only the Release workflow identity a narrow `main` update exception. Do not force-push or place the release commit only on a temporary branch.

## Publishing a release

1. Merge reviewed feature and fix changes to `main` and confirm its normal push CI is green.
2. Open **Actions -> Release -> Run workflow**, select `main`, and enter `version: X.Y.Z`.
3. The workflow validates the PEP 440 version and starting CI, commits `chore: release vX.Y.Z [skip ci]` on `main`, runs Linux Python 3.13/3.14 and macOS Python 3.14 tests, builds and smoke-tests the wheel and sdist, and generates `SHA256SUMS`.
4. Approve the pending `release` environment deployment. After validation and approval the workflow makes an immutable annotated tag on the exact release commit and creates or repairs the GitHub Release with the validated assets.

The version-only commit skips redundant normal CI because the release workflow validates its exact SHA. If a run fails after the commit, rerun with the same version while that commit remains current `main`; the workflow reuses it. If `main` moves, the retry stops. An existing tag is accepted only if it points to that same commit and is never moved.

Do not dispatch a release until publication is explicitly authorized.
