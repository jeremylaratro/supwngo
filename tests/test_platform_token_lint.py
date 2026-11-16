"""Fixture-level self-tests of the platform-token lint grammar (W-3 step 2).

Deliberately does NOT assert the real tree is clean; the tree-wide gate is
enabled in a later step once literals are migrated.
"""
import importlib.util
import textwrap
from pathlib import Path

import pytest

from supwngo.core import success_oracle

_SPEC = importlib.util.spec_from_file_location(
    "check_platform_tokens",
    Path(__file__).resolve().parent.parent / "scripts" / "check_platform_tokens.py",
)
lint = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(lint)

# Frozen exemptions: (location, justification).  The neutral oracle shape needs
# no token exemption (it carries none by construction); kernel/templates.py is
# parameterised in a later step, never exempted.
EXEMPTIONS = (
    (
        "supwngo/core/success_oracle.py:NEUTRAL_FLAG_SHAPE",
        "carries no platform token by construction; asserted below, not exempted",
    ),
)


def _hits(src):
    return lint.scan_source(textwrap.dedent(src))


@pytest.mark.parametrize(
    "lit",
    ["HTB", "hackthebox", "HackTheBox", "PicoCTF", "csaw", "CSAW", "asis", "ASIS",
     "x htb y", "htb_flag", "flag{", r"flag\{", "CTF{", r"htb\{", "PicoCTF{"],
)
def test_flags_tokens_and_brace_forms(lit):
    assert _hits(f"x = {lit!r}\n")


def test_bytes_constants_flagged():
    assert _hits("x = b'HTB{abc}'\n")
    assert _hits("x = b'flag{'\n")


def test_fstring_segments_flagged():
    assert _hits("y=1\nx = f'prefix hackthebox {y} tail'\n")
    assert _hits("y=1\nx = f'{y} flag{{'\n")


def test_docstrings_excluded():
    src = '''
    """module HTB flag{ doc"""
    class C:
        """class picoctf doc"""
        def f(self):
            """func csaw doc"""
            return 1
    async def g():
        """asis doc"""
    '''
    assert _hits(src) == []


def test_non_docstring_bare_string_flagged():
    assert _hits("x = 1\n'HTB second string'\n")
    assert _hits("def f():\n    x = 1\n    'HTB'\n")


def test_comments_not_constants():
    assert _hits("x = 1  # HTB flag{ picoctf\n# csaw\n") == []


def test_generated_comment_string_flagged():
    assert _hits("script = '# Challenge: HackTheBox tictacpwn'\n")


@pytest.mark.parametrize("lit", ["stage3_basis", "basis", "OASIS", "oasis", "Basis"])
def test_asis_is_word_bounded(lit):
    assert _hits(f"x = {lit!r}\n") == []


def test_planted_executable_token_fails_cli(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("def run():\n    return 'HTB{x}'\n")
    assert lint.main([str(bad)]) == 1


def test_clean_fixture_passes_cli(tmp_path):
    ok = tmp_path / "ok.py"
    ok.write_text('"""doc HTB"""\nx = "stage3_basis"  # htb\n')
    assert lint.main([str(ok)]) == 0


def test_neutral_oracle_shape_carries_no_token():
    assert lint.scan_source(
        f"x = {success_oracle.NEUTRAL_FLAG_SHAPE!r}\n"
    ) == []
    assert all(just for _, just in EXEMPTIONS)
