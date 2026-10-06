"""Offline wheel/sdist smoke check, run with the clean installation's Python."""

from importlib.metadata import distribution
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> None:
    installed = distribution("credential-vault")
    posts = [entry for entry in installed.entry_points if entry.group == "beauty.post"]
    assert [(entry.name, entry.value) for entry in posts] == [
        ("credential-vault", "credential_vault.tools.post")
    ], "one installed post entry point is required"
    module = posts[0].value
    with tempfile.TemporaryDirectory() as directory:
        context = {
            "contract_version": 1,
            "deployment_id": "0" * 32,
            "distribution": "credential-vault",
            "environment": "beauty",
            "prefix": sys.prefix,
            "reconcile": True,
            "operation": "deploy",
            "prior_version": None,
            "recovery_directory": str(Path(directory) / "unused-recovery"),
            "intent": {},
        }
        for prior_version, reconcile in ((None, True), (installed.version, False)):
            context.update(prior_version=prior_version, reconcile=reconcile)
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-m", module],
                input=json.dumps(context), text=True, capture_output=True,
                cwd=directory, timeout=10, check=True,
            )
            assert result.stderr == ""
            assert json.loads(result.stdout) == {
                "status": "unchanged",
                "message": "no package-owned state reconciliation required",
            }
        assert list(Path(directory).iterdir()) == [], "post must create no state"
    print(f"{installed.metadata['Name']} {installed.version}: installed post entry-point check passed")


if __name__ == "__main__":
    main()
