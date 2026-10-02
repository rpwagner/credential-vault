"""Execute the release approval guard against matching and moved main SHAs."""
from pathlib import Path
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize("workflow", ["release.yml"])
def test_approved_sha_guard_stops_before_checkout_or_version_mutation(workflow):
    text = (ROOT / ".github/workflows" / workflow).read_text()
    block = text.split("      - name: Require approved main SHA\n", 1)[1]
    script = block.split("        run: |\n", 1)[1].split("      - ", 1)[0]
    script = "\n".join(line.removeprefix("          ") for line in script.splitlines())
    for expected, actual, allowed in [
        ("", "a" * 40, True),
        ("a" * 40, "a" * 40, True),
        ("a" * 40, "b" * 40, False),
        ("invalid", "a" * 40, False),
    ]:
        result = subprocess.run(["bash", "-c", script],
            env={"EXPECTED_SHA": expected, "GITHUB_SHA": actual}, capture_output=True)
        assert (result.returncode == 0) == allowed
    assert text.index("Require approved main SHA") < text.index("actions/checkout@") < text.index("git commit")
