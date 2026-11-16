"""W-3 batch 5: the two static flag classifiers now route through the oracle.

Before/after tests that the platform-neutral helpers in
``supwngo.core.success_oracle`` reproduce the historical behaviour of
``analysis/strings.py:_is_flag_pattern`` (W-0001..0006 + the ``FLAG_`` branch)
and ``exploit/walkthrough/facts.py:_is_flagish`` (W-0141) on representative
inputs, while carrying no platform token.
"""

from __future__ import annotations

import re

from supwngo.analysis.strings import StringAnalyzer
from supwngo.core.success_oracle import is_flag_shaped_text, is_flagish_bytes

# --- strings.py: the historical 7-pattern classifier -----------------------

# Reconstructed "before" oracle, verbatim from the pre-W-3 ``_is_flag_pattern``.
_OLD_STRINGS_PATTERNS = [
    r"flag\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"CSAW\{[^}]+\}",
    r"ASIS\{[^}]+\}",
    r"FLAG_[A-Za-z0-9]+",
]


def _old_is_flag_pattern(value: str) -> bool:
    return any(re.search(p, value, re.IGNORECASE) for p in _OLD_STRINGS_PATTERNS)


# Representative inputs where the old and new classifiers must agree: a
# word-brace flag across every old platform prefix, a FLAG_<alnum> token, and
# negatives (ordinary text, the benign ``stage3_basis``, a short body).
_STRINGS_AGREE = [
    "flag{abcd1234}",
    "CTF{abcd1234}",
    "HTB{abcd1234}",
    "picoCTF{abcd1234}",
    "CSAW{abcd1234}",
    "ASIS{abcd1234}",
    "FLAG_SECRET1",
    "flag_secret1",
    "just an ordinary string",
    "stage3_basis",
    "x",
    "",
]


def test_strings_flag_pattern_before_after_agree():
    analyzer = StringAnalyzer.__new__(StringAnalyzer)  # _is_flag_pattern ignores self
    for value in _STRINGS_AGREE:
        old = _old_is_flag_pattern(value)
        new = analyzer._is_flag_pattern(value)
        assert new is old, (value, old, new)
        assert new is is_flag_shaped_text(value), value


def test_strings_flag_pattern_is_platform_neutral():
    analyzer = StringAnalyzer.__new__(StringAnalyzer)
    # The new classifier is platform-neutral: a non-platform word-brace flag
    # matches (the old classifier only knew six named platforms).
    assert analyzer._is_flag_pattern("myapp{deadbeef}")
    assert not _old_is_flag_pattern("myapp{deadbeef}")


# --- facts.py: the historical redaction fail-safe --------------------------

_OLD_FACTS_RE = re.compile(rb"(flag|FLAG|ctf|CTF)\s*\{|\{[A-Za-z0-9_]{4,}\}")


def _old_is_flagish(data: bytes) -> bool:
    return bool(_OLD_FACTS_RE.search(data))


# Inputs where old and new redaction agree.
_FACTS_AGREE = [
    b"flag{abcd1234}",
    b"FLAG {abcd}",       # whitespace between word and brace
    b"{abcd}",            # prefixless, 4 chars
    b"{abcd1234}",        # prefixless, long
    b"{abc}",             # prefixless body < 4: not redacted
    b"FLAG_SECRET1",      # bare token, no brace: not redacted
    b"value = { 1 }",     # ordinary brace text: not over-redacted
    b"plain output line",
]


def test_facts_redaction_before_after_agree():
    for data in _FACTS_AGREE:
        old = _old_is_flagish(data)
        new = is_flagish_bytes(data)
        assert new is old, (data, old, new)


def test_facts_redaction_preserves_both_triggers():
    # (a) prefix-only / truncation-tolerant: an opening brace alone, no close.
    assert is_flagish_bytes(b"someword{")
    assert is_flagish_bytes(b"flag{")
    # (b) prefixless.
    assert is_flagish_bytes(b"{deadbeef}")
    # Not over-redacted.
    assert not is_flagish_bytes(b"value = { 1 }")
    assert not is_flagish_bytes(b"no braces here at all")


def test_facts_redaction_is_platform_neutral():
    # Any word before a brace is redacted now, not only the platform words.
    assert is_flagish_bytes(b"myapp{deadbeef}")
    assert not _old_is_flagish(b"myapp{")  # old fired only on platform words
    assert is_flagish_bytes(b"myapp{")
