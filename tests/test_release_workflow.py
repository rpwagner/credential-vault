from pathlib import Path

ROOT = Path(__file__).parents[1]
RELEASE = (ROOT / ".github/workflows/release.yml").read_text()
CI = (ROOT / ".github/workflows/ci.yml").read_text()


def test_release_commits_version_and_keeps_approval() -> None:
    assert "workflow_dispatch:\n    inputs:\n      version:" in RELEASE
    assert "actions/workflows/ci.yml/runs" in RELEASE
    assert 'git commit -m "chore: release $tag [skip ci]"' in RELEASE
    assert "git push origin HEAD:refs/heads/main" in RELEASE
    assert "ref: ${{ needs.metadata.outputs.sha }}" in RELEASE
    assert "name: release" in RELEASE
    assert RELEASE.index("git commit -m") < RELEASE.index("python -m build")
    assert RELEASE.index("Run test suite") < RELEASE.index("git tag --annotate")
    assert "git fetch --tags --force" not in RELEASE
    assert "gh release upload" in RELEASE


def test_release_keeps_platform_and_distribution_coverage() -> None:
    assert "ubuntu-latest" in RELEASE
    assert "macos-latest" in RELEASE
    assert 'python-version: "3.13"' in RELEASE
    assert 'python-version: "3.14"' in RELEASE
    assert "Install and smoke-test wheel" in RELEASE
    assert "Install and smoke-test source distribution" in RELEASE
    assert "SHA256SUMS" in RELEASE
    assert "needs: [metadata, test, package]" in RELEASE
    assert "    tags:\n      - v*" not in CI
