"""Offline wheel/sdist smoke check, run with the clean installation's Python."""

import base64
import hashlib
from importlib.metadata import distribution
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> None:
    installed = distribution("credential-vault")
    matches = [file for file in installed.files or ()
               if str(file).endswith("/tools/post.py")]
    assert len(matches) == 1, "one installed post script is required"
    file = matches[0]
    script = Path(file.locate()).absolute()
    assert not script.is_symlink()
    assert script.resolve().is_relative_to(Path(sys.prefix).resolve())
    digest = base64.urlsafe_b64encode(hashlib.sha256(script.read_bytes()).digest()).decode().rstrip("=")
    assert file.hash is not None and file.hash.mode == "sha256"
    assert file.hash.value == digest, "installed post script must match RECORD"
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
                [sys.executable, "-I", "-B", str(script)],
                input=json.dumps(context), text=True, capture_output=True,
                cwd=directory, timeout=10, check=True,
            )
            assert result.stderr == ""
            assert json.loads(result.stdout) == {
                "status": "unchanged",
                "message": "no package-owned state reconciliation required",
            }
        assert list(Path(directory).iterdir()) == [], "post must create no state"
    print(f"{installed.metadata['Name']} {installed.version}: installed post check passed")


if __name__ == "__main__":
    main()
