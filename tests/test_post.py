"""Post execution never opens credentials, discovers state, or contacts services."""

import fcntl
import json
from pathlib import Path
import secrets
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
POST = ROOT / "src/credential_vault/tools/post.py"

# Load the script before denying access. A separate interpreter keeps the audit
# guard isolated from pytest and makes attempted authority violations fail closed.
GUARDED = r'''
import json, pathlib, sys
code = compile(pathlib.Path(sys.argv[1]).read_bytes(), sys.argv[1], 'exec')
def deny(event, args):
    if (event in {'open', 'os.listdir', 'os.scandir', 'os.mkdir', 'os.remove',
                  'os.rename', 'os.chmod', 'os.system'}
            or event.startswith(('socket.', 'subprocess.', 'fcntl.'))
            or (event == 'import' and args[0].startswith(
                ('credential_vault', 'keyring', 'globus_sdk')))):
        raise AssertionError('post attempted forbidden access')
sys.addaudithook(deny)
exec(code, {'__name__': sys.argv[2]})
'''


def context(tmp_path, **updates):
    value = {
        "contract_version": 1,
        "deployment_id": "0" * 32,
        "distribution": "credential-vault",
        "environment": "beauty",
        "prefix": sys.prefix,
        "reconcile": True,
        "operation": "deploy",
        "prior_version": None,
        "recovery_directory": str(tmp_path / "absent"),
        "intent": {},
    }
    value.update(updates)
    return value


def invoke(tmp_path, payload, *, module_name="__main__"):
    return subprocess.run(
        [sys.executable, "-I", "-B", "-c", GUARDED, str(POST), module_name],
        input=payload, capture_output=True, cwd=tmp_path, timeout=10,
    )


def test_missing_vault_and_keys_need_no_bootstrap(tmp_path):
    result = invoke(tmp_path, json.dumps(context(tmp_path)).encode())
    assert result.returncode == 0
    assert result.stderr == b""
    assert json.loads(result.stdout)["status"] == "unchanged"
    assert list(tmp_path.iterdir()) == []


def test_import_does_not_run_post(tmp_path):
    result = invoke(tmp_path, b"invalid input", module_name="credential_vault.tools.post")
    assert result.returncode == 0
    assert result.stdout == result.stderr == b""
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("environment", ["beauty", "inference-core"])
@pytest.mark.parametrize("reconcile", [True, False])
@pytest.mark.parametrize("operation,prior_version", [
    ("deploy", None), ("deploy", "0.0.9"), ("deploy", "0.1.0"),
    ("deploy", "9.0.0"), ("recover", "9.0.0"),
])
def test_noop_preserves_existing_and_missing_state(
    tmp_path, environment, reconcile, operation, prior_version, initialized_vault,
):
    vault, provider, vault_path = initialized_vault
    vault.set_password("synthetic-service", "synthetic-account", secrets.token_urlsafe())
    original = vault_path.read_bytes()
    key = provider.key
    key_writes = list(provider.set_values)
    lock = vault.lock_path.open("rb")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        payload = json.dumps(context(
            tmp_path, environment=environment, reconcile=reconcile,
            operation=operation, prior_version=prior_version,
        )).encode()
        for _ in range(2):
            result = invoke(tmp_path, payload)
            assert result.returncode == 0, result.stderr
            assert result.stderr == b""
            assert json.loads(result.stdout) == {
                "status": "unchanged",
                "message": "no package-owned state reconciliation required",
            }
        assert vault_path.read_bytes() == original
        assert provider.key == key
        assert provider.set_values == key_writes
        assert provider.delete_count == 0
        assert not (tmp_path / "absent").exists()
    finally:
        lock.close()


@pytest.mark.parametrize("updates", [
    {"contract_version": 2}, {"contract_version": True},
    {"distribution": "other-owner"}, {"environment": "unknown"},
    {"operation": "rotate"}, {"operation": []}, {"reconcile": 1},
    {"intent": {"initialize": True}}, {"intent": None},
])
def test_unsupported_context_fails_without_echo_or_access(tmp_path, updates):
    value = context(tmp_path, **updates)
    marker = secrets.token_urlsafe()
    value["private-input"] = marker
    result = invoke(tmp_path, json.dumps(value).encode())
    assert result.returncode == 1
    assert result.stderr == b""
    assert marker.encode() not in result.stdout
    assert json.loads(result.stdout) == {
        "status": "failed",
        "message": "invalid or unsupported Vault deployment context",
    }
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("payload", [
    b"", b"{", b"[]", b"null", b"\xff", b"{} {}", b" " * 65537,
    b"[" * 2000 + b"]" * 2000,
])
def test_invalid_input_has_bounded_failure(tmp_path, payload):
    result = invoke(tmp_path, payload)
    assert result.returncode == 1
    assert result.stderr == b""
    assert json.loads(result.stdout)["status"] == "failed"
    assert len(result.stdout) < 512
    assert list(tmp_path.iterdir()) == []
