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

## Reviewed cryptfile package source

Vault requires the unchanged wheel from `rpwagner/keyrings.cryptfile` v1.5.0.
`tools/cryptfile-source.json` records its annotated tag object, release commit,
release/asset IDs, filename, size and reviewed SHA256. Later fork-main changes
are not adopted by this packaging change. The tag is unsigned and the GitHub
release is not marked immutable; this is a reviewed byte/hash record, not a
claim of signed build attestation. Any changed artifact requires separate review.

Use `ghr-pypi==2026.8.14.1` mirror mode, which already owns authenticated asset
downloads, digest verification, cache reuse, metadata extraction and PEP 503/691
generation. It preserves the release bytes and emits relative local links with
SHA256 fragments. No Vault runtime dependency on this tool is introduced.

For standalone development, from this checkout with an existing GitHub login:

```bash
python -m pip install ghr-pypi==2026.8.14.1
source_dir="$(mktemp -d)"
GHR_PYPI_TOKEN="$(gh auth token)" ghr-pypi index rpwagner/keyrings.cryptfile \
  --mirror --out "$source_dir/mirror"
fork_wheel="$(python tools/check_cryptfile_source.py --mirror "$source_dir/mirror")"
python -m pip download --only-binary=:all: --dest "$source_dir/dependencies" \
  ".[test]" "$fork_wheel" 'setuptools>=77' wheel
rm "$source_dir/dependencies/$(basename "$fork_wheel")"
export PIP_CONFIG_FILE=/dev/null
export PIP_INDEX_URL="$(python -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).as_uri()+"/")' "$source_dir/mirror/simple")"
export PIP_EXTRA_INDEX_URL=
export PIP_FIND_LINKS="$source_dir/dependencies"
export PIP_ONLY_BINARY=keyrings.cryptfile
python -m pip install -e ".[test]" --report "$source_dir/install.json"
python tools/check_cryptfile_source.py --mirror "$source_dir/mirror" --report "$source_dir/install.json"
python -m pip check
python -m pytest
```

The explicit local fork input is used only while pip stages public dependencies;
pip owns that compatible closure. Remove its staged copy so installation can
resolve the fork only through the verified index. The staging directory is
disposable validation/download state, not a maintained lockfile or a second
dependency registry. Do not mirror or publish private artifacts to a public host.

**Source limitation:** PEP 508 cannot bind an ordinary requirement to a
repository/hash, and pip pools candidates from its main/extra indexes and
find-links locations without source priority. A `==1.5.0` pin and a hashed link
in one index cannot rule out unrelated same-name/version bytes in another.
The minimal demonstrated safe path uses the verified local mirror as the only
index and standard pip-staged public wheels as find-links, excluding cryptfile.
An existing namespace-filtered package source is another possible consumer
configuration; this repository does not implement a source server or resolver.
Retain the mirror provenance record with consumer installation evidence.

CI and release jobs prepare the same sources, run normal platform tests, and
exercise clean wheel and sdist installation outside the checkout. The install
checker disables pip caches/config, blocks and records HTTP(S), verifies the
dry-run selection before installation and the actual install report afterwards,
and runs `pip check`, public import and installed-post smoke checks. Zero attempted
HTTP(S) requests proves installation does not contact the GitHub release URL.
Negative tests reject changed bytes, remote index links and wrong report
source/hash/version. These checks do not access a user's vault or credentials.

Beauty Maintainer must include the maintained fork in its mirror inputs and
enforce source selection before either environment rebuild (Beauty Runtime #323).
That orchestration is outside this package. Ordinary unrestricted multiple-index
installation is not validated as preserving fork identity.

After an authorized Vault release, separately verify its published wheel/sdist
checksums and ordinary dependency metadata, refresh the consumer mirror, and
exercise the selected release through the supported host's environment recipe.
Tagged Vault artifact and supported-host deployment evidence remain pending until
those separately authorized operations; they are not claimed by source CI.

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

The wheel and source distribution expose the `credential-vault` entry in the
`beauty.post` group, targeting `credential_vault.tools.post:main`.
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
including entry-point discovery and repeated installed invocation:

```bash
/absolute/clean-environment/bin/python -I -B tools/check_installed_post.py
```

The checker loads the installed entry point in a disposable directory and verifies no
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
