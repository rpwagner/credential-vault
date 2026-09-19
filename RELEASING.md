# Releasing

Tagged releases are tested, built, and published by the `CI` workflow. The workflow pauses before publication for approval through the protected `release` environment.

## One-time repository setup

Before creating the first release tag:

1. In **Settings → Environments**, create an environment named `release`.
2. Add at least one required reviewer.
3. Disable administrator bypass so every publication requires approval.
4. Restrict deployment tags to `v*`.

If the person pushing the tag will also approve the release, leave **Prevent self-review** disabled. Enable it when a second reviewer is available and independent approval is required.

GitHub stores these protection rules in repository settings rather than in the workflow file.

## Publishing a release

1. Merge the version and release-note changes to `main`.
2. Create and push an annotated tag matching the package version, such as `v0.1.0`.
3. Wait for the complete test matrix and distribution checks to pass.
4. Review and approve the pending `release` environment deployment.

After approval, the workflow creates a GitHub Release with the wheel, source distribution, and SHA-256 checksums.

Do not publish a release unless explicitly instructed.
