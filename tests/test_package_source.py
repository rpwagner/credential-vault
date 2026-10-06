"""The name/version alone must never be treated as fork provenance."""

import hashlib
import importlib.util
from importlib.metadata import distribution
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("check_cryptfile_source", ROOT / "tools/check_cryptfile_source.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


@pytest.fixture
def mirror(tmp_path, monkeypatch):
    payload = b"synthetic artifact for source validator tests"
    source = dict(checker.SOURCE, size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(checker, "SOURCE", source)
    wheel = tmp_path / "files/keyrings-cryptfile" / source["filename"]
    wheel.parent.mkdir(parents=True)
    wheel.write_bytes(payload)
    page = tmp_path / "simple/keyrings-cryptfile/index.html"
    page.parent.mkdir(parents=True)
    page.write_text(f'<a href="../../files/keyrings-cryptfile/{wheel.name}#sha256={source["sha256"]}">{wheel.name}</a>')
    return tmp_path, wheel, page


def test_ordinary_requirement_has_no_release_url():
    requirements = distribution("credential-vault").requires
    cryptfile = [value for value in requirements if value.startswith("keyrings.cryptfile")]
    assert cryptfile == ["keyrings.cryptfile==1.5.0"]
    assert not any("github.com" in value for value in requirements)


def test_reviewed_mirror_and_report(mirror, tmp_path):
    root, wheel, _ = mirror
    assert checker.check_mirror(root) == wheel
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"install": [{
        "metadata": {"name": "keyrings_cryptfile", "version": "1.5.0"},
        "download_info": {"url": wheel.as_uri(), "archive_info": {"hashes": {"sha256": checker.SOURCE["sha256"]}}},
    }]}))
    checker.check_report(report, root)


def test_changed_artifact_is_rejected(mirror):
    root, wheel, _ = mirror
    wheel.write_bytes(b"unreviewed bytes")
    with pytest.raises(ValueError, match="differs from the reviewed release"):
        checker.check_mirror(root)


@pytest.mark.parametrize("link", [
    "https://github.com/rpwagner/keyrings.cryptfile/releases/download/v1.5.0/",
    "https://files.pythonhosted.org/",
])
def test_remote_index_link_is_rejected(mirror, link):
    root, wheel, page = mirror
    page.write_text(f'<a href="{link}{wheel.name}#sha256={checker.SOURCE["sha256"]}">wheel</a>')
    with pytest.raises(ValueError, match="local artifact links"):
        checker.check_mirror(root)


def test_remote_candidate_added_beside_reviewed_link_is_rejected(mirror):
    root, wheel, page = mirror
    page.write_text(page.read_text() + f'<a href="https://files.pythonhosted.org/{wheel.name}">other</a>')
    with pytest.raises(ValueError, match="local artifact links"):
        checker.check_mirror(root)


@pytest.mark.parametrize("change", ["source", "hash", "version", "missing", "duplicate"])
def test_unreviewed_pip_selection_is_rejected(mirror, tmp_path, change):
    root, wheel, _ = mirror
    item = {
        "metadata": {"name": "keyrings.cryptfile", "version": "1.5.0"},
        "download_info": {"url": wheel.as_uri(), "archive_info": {"hashes": {"sha256": checker.SOURCE["sha256"]}}},
    }
    if change == "source":
        item["download_info"]["url"] = "https://files.pythonhosted.org/" + wheel.name
    elif change == "hash":
        item["download_info"]["archive_info"]["hashes"]["sha256"] = "0" * 64
    elif change == "version":
        item["metadata"]["version"] = "1.5.1"
    installs = [] if change == "missing" else [item, item] if change == "duplicate" else [item]
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"install": installs}))
    with pytest.raises(ValueError):
        checker.check_report(report, root)
