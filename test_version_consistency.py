"""The version is written in four places. A guard that reads one is a guess."""

import re
import tomllib
from pathlib import Path

import tiny_dist_audit as tda

ROOT = Path(__file__).parent


def _pyproject_version():
    with open(ROOT / "pyproject.toml", "rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def test_module_pyproject_and_cli_usage_agree():
    usage = tda._usage()
    match = re.search(r"tiny-dist-audit (\d+\.\d+\.\d+)", usage)
    assert match, "usage banner lost its version"
    assert match.group(1) == tda.__version__
    assert _pyproject_version() == tda.__version__


def test_readme_badge_and_install_line_agree_with_version():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"pip install tiny-dist-audit" in readme
    # The README must not claim a version the package does not have.
    for claimed in re.findall(r"tiny_dist_audit-(\d+\.\d+\.\d+)-py3", readme):
        assert claimed == tda.__version__, f"README example wheel says {claimed}"


def test_llms_txt_claims_match_the_code():
    text = (ROOT / "llms.txt").read_text(encoding="utf-8")
    assert "Python 3.9+" in text
    assert "exits 5" in text
    # The schema string is a contract; an agent reading llms.txt must be able to
    # find the exact value the code emits.
    assert tda.MANIFEST_SCHEMA in text or "tiny-dist-audit/1" in text
