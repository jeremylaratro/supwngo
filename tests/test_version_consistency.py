"""The version is declared in several places; this pins them to agree.

Before this test the string "1.0.0" was hardcoded in five locations
(supwngo/__init__.py, pyproject.toml, setup.py, and twice in
supwngo/api/server.py). Nothing checked them against each other, so a release
could bump three and leave two behind and every suite would still pass -- the
API would then report a version the package had not been at for two releases.

The two API sites now read supwngo.__version__ rather than repeating the
literal, which is why this file also guards against the literal coming back.

supwngo/__init__.py is the single source of truth: it is what `supwngo
--version` prints, via click.version_option in cli.py.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

import supwngo

REPO_ROOT = Path(__file__).resolve().parent.parent

SEMVER = re.compile(r"^\d+\.\d+\.\d+([-+][0-9A-Za-z.\-]+)?$")


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text()
    # Only the [project] table's own version, not a dependency pin.
    m = re.search(r"^version\s*=\s*\"([^\"]+)\"", text, re.MULTILINE)
    assert m, "no version found in pyproject.toml -- the parser, not the file, may be wrong"
    return m.group(1)


def _setup_py_version() -> str:
    text = (REPO_ROOT / "setup.py").read_text()
    m = re.search(r"^\s*version\s*=\s*\"([^\"]+)\"", text, re.MULTILINE)
    assert m, "no version found in setup.py -- the parser, not the file, may be wrong"
    return m.group(1)


def test_package_version_is_a_semver_string():
    assert SEMVER.match(supwngo.__version__), (
        f"supwngo.__version__ is {supwngo.__version__!r}, not a SemVer string"
    )


def test_all_declared_versions_agree():
    """The assertion that would have caught a partial bump."""
    declared = {
        "supwngo/__init__.py": supwngo.__version__,
        "pyproject.toml": _pyproject_version(),
        "setup.py": _setup_py_version(),
    }
    distinct = set(declared.values())
    assert len(distinct) == 1, (
        f"version declarations disagree: {declared}. supwngo/__init__.py is the "
        f"source of truth; bring the packaging files to it."
    )


def test_cli_version_flag_reports_the_package_version():
    """`--version` is what a user actually sees; assert on the real invocation
    rather than on the constant it is supposed to read."""
    proc = subprocess.run(
        [sys.executable, "-m", "supwngo.cli", "--version"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, f"--version exited {proc.returncode}: {proc.stderr[-500:]}"
    assert supwngo.__version__ in proc.stdout, (
        f"--version printed {proc.stdout.strip()!r}, which does not contain "
        f"the package version {supwngo.__version__!r}"
    )


@pytest.mark.parametrize("relpath", ["supwngo/api/server.py"])
def test_api_server_does_not_hardcode_a_version_literal(relpath):
    """Regression guard: these two sites each carried their own "1.0.0" and
    silently disagreed with the package. They now read __version__."""
    text = (REPO_ROOT / relpath).read_text()
    hardcoded = re.findall(r"version\s*=\s*\"\d+\.\d+\.\d+\"", text)
    assert not hardcoded, (
        f"{relpath} hardcodes a version literal {hardcoded}; read "
        f"supwngo.__version__ instead so it cannot drift"
    )


def test_changelog_documents_the_current_version():
    """A released version must appear in the changelog. Catches a bump that
    never got its release notes."""
    text = (REPO_ROOT / "CHANGELOG.md").read_text()
    assert f"## [{supwngo.__version__}]" in text, (
        f"CHANGELOG.md has no '## [{supwngo.__version__}]' section; a version "
        f"bump without release notes leaves users unable to see what changed"
    )
