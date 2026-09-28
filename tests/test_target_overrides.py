"""`--win` / `--ret2` / `--rop`: the operator's return-target overrides.

WHAT THESE TESTS ARE GUARDING AGAINST
-------------------------------------
An override is a feature whose failure mode is silence. If `--win` is parsed,
stored, logged, and then ignored by the code that builds the payload, every
observable signal still looks right: the flag is accepted, the run proceeds, and
on most targets it even SUCCEEDS -- because auto-detection quietly supplied the
address instead and auto-detection is usually correct. A test that only asserts
"the run succeeded with --win" therefore proves nothing at all.

So the central test here (:func:`test_win_override_redirects_the_payload`) does
not assert success. It asserts that **the address in the generated script
changes to the one the operator named**, and it points the override at a
function that is NOT a payoff so that honouring it makes the run FAIL. Those two
assertions together are what rule out a silent fallback:

* address changed  -> the override reached the payload builder;
* run failed       -> the framework did not quietly revert to the address it
  preferred when the operator's choice turned out not to work.

Reversed, either one alone is satisfied by a broken implementation.

THE FIXTURE IS A REDIRECTION FIXTURE, NOT A "DETECTION FAILS" ONE
----------------------------------------------------------------
`unnamed_payoff.c`'s `stage_two` is named to match no win-function heuristic,
and the first version of this file tried to use it to prove `--win` makes an
otherwise-unsolvable target solvable. Measured, that was wrong:
`WinFunctionFinder._find_by_calls` finds any function calling `system`/`execve`,
so `solve --strategy ret2win` already succeeds on it with no flag at all. The
fixture's own header records that measurement. What it gives us instead is a
baseline address to differ from, which is what every test below relies on.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
FIXTURE_SRC = REPO / "tests" / "fixtures" / "target_overrides" / "unnamed_payoff.c"

#: No PIE and no canary so the two function addresses are fixed and comparable
#: between runs -- the whole point of the fixture is a stable baseline address.
_CFLAGS = ["-fno-stack-protector", "-no-pie", "-O0"]


@pytest.fixture(scope="module")
def target(tmp_path_factory) -> Path:
    """Compile the fixture. Source is committed; the ELF is not."""
    out = tmp_path_factory.mktemp("target_overrides") / "unnamed_payoff"
    subprocess.run(
        ["gcc", *_CFLAGS, "-o", str(out), str(FIXTURE_SRC)],
        check=True, capture_output=True, text=True,
    )
    return out


@pytest.fixture(scope="module")
def addrs(target) -> dict:
    """``{name: address}`` for the fixture's two interesting functions.

    Read out of the built ELF rather than hardcoded: the addresses depend on the
    local gcc, and a hardcoded 0x4011d6 would turn a toolchain difference into a
    confusing assertion failure about override behaviour.
    """
    from supwngo.core.binary import Binary

    binary = Binary.load(str(target))
    out = {}
    for name in ("stage_two", "handle"):
        entry = binary.symbols.get(name)
        assert entry is not None, f"fixture lost its {name} symbol"
        out[name] = int(getattr(entry, "address", entry))
    assert out["stage_two"] != out["handle"]
    return out


def _solve(target: Path, out_script: Path, *flags: str, timeout: float = 180.0):
    """Run `solve --strategy ret2win` and return ``(result_json, script_text)``.

    `--strategy ret2win` pins the technique so a difference between two runs
    cannot be explained by the ladder picking something else, and `--no-legacy`
    keeps the legacy engine from supplying a solve a canonical executor would be
    credited for.
    """
    cmd = [
        sys.executable, "-m", "supwngo.cli", "solve", str(target),
        "--no-legacy", "--strategy", "ret2win", "--timeout", "5",
        "-o", str(out_script), "--json", *flags,
    ]
    proc = subprocess.run(
        cmd, cwd=str(REPO), capture_output=True, text=True, timeout=timeout,
    )
    script = out_script.read_text() if out_script.exists() else ""
    return _parse_json_block(proc.stdout), script


def _parse_json_block(stdout: str):
    """The result object out of `--json` stdout, or ``None``.

    `_emit_json` pretty-prints, so the object spans many lines and a
    line-by-line "starts with {" scan finds only a bare "{" and parses nothing --
    which silently returned None and made two override tests fail on their own
    BASELINE assertion rather than on anything about overrides. Parse the whole
    tail from the first brace instead.
    """
    start = stdout.find("{")
    if start == -1:
        return None
    try:
        return json.loads(stdout[start:])
    except json.JSONDecodeError:
        pass
    # Banner/log lines can precede or follow the object; fall back to a
    # decoder that stops at the end of the first complete value.
    try:
        obj, _end = json.JSONDecoder().raw_decode(stdout[start:])
        return obj
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------
# Unit: address parsing. Every case here is a control, including the ones
# that must NOT parse.
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "spec,expected",
    [
        ("0x401196", 0x401196),
        ("4198806", 4198806),
        ("0o777", 0o777),
        ("0b1010", 0b1010),
        ("deadbeef", 0xDEADBEEF),   # unprefixed hex, unambiguous (has a-f)
        ("1234", 1234),             # decimal stays decimal, never reread as hex
        ("main", None),
        ("win", None),
        ("get_flag", None),
        ("", None),
        ("0xZZ", None),
        # Regression: `int("-5", 0)` succeeds, so an early version returned -5
        # as an "address". Packed into a payload that becomes 0xff..fb, i.e. a
        # resolved-looking target that can only crash. Found by a control, not
        # by review.
        ("-5", None),
        ("-0x10", None),
    ],
)
def test_parse_address(spec, expected):
    from supwngo.exploit.pipeline.target_overrides import parse_address

    assert parse_address(spec) == expected


# --------------------------------------------------------------------------
# Unit: spec resolution against a real ELF.
# --------------------------------------------------------------------------

def test_resolve_binary_symbol(target, addrs):
    from supwngo.core.binary import Binary
    from supwngo.exploit.pipeline.target_overrides import (
        RESOLUTION_BINARY_SYMBOL, resolve_target,
    )

    resolved, warning = resolve_target("stage_two", Binary.load(str(target)))
    assert warning is None
    assert resolved.address == addrs["stage_two"]
    assert resolved.resolution == RESOLUTION_BINARY_SYMBOL
    assert resolved.name == "stage_two"
    assert not resolved.libc_relative
    assert not resolved.is_rop_gadget


def test_resolve_raw_address_matches_the_symbol_it_names(target, addrs):
    from supwngo.core.binary import Binary
    from supwngo.exploit.pipeline.target_overrides import (
        RESOLUTION_RAW, resolve_target,
    )

    binary = Binary.load(str(target))
    resolved, warning = resolve_target(hex(addrs["stage_two"]), binary)
    assert warning is None
    assert resolved.address == addrs["stage_two"]
    assert resolved.resolution == RESOLUTION_RAW
    assert resolved.name == ""


def test_unknown_symbol_warns_and_does_not_resolve(target):
    """The operator's chosen behaviour: warn and fall back, never hard-fail."""
    from supwngo.core.binary import Binary
    from supwngo.exploit.pipeline.target_overrides import resolve_target

    resolved, warning = resolve_target(
        "definitely_not_a_symbol_xyz", Binary.load(str(target))
    )
    assert resolved is None
    assert warning and "falling back to auto-detection" in warning
    # The message must name every step that was tried. An earlier version
    # reported only the libc miss ("pass --libc"), sending the operator to fix a
    # libc that was never the problem.
    assert "not a binary symbol" in warning


def test_rop_flag_marks_the_target_as_a_gadget(target, addrs):
    from supwngo.core.binary import Binary
    from supwngo.exploit.pipeline.target_overrides import resolve_target

    resolved, _ = resolve_target(
        hex(addrs["handle"]), Binary.load(str(target)), rop=True, role="ret2",
    )
    assert resolved.is_rop_gadget is True
    assert "ROP gadget" in resolved.label


def test_no_spec_is_not_a_warning(target):
    """``None`` means "flag absent", which must be silent, not a complaint."""
    from supwngo.core.binary import Binary
    from supwngo.exploit.pipeline.target_overrides import resolve_target

    assert resolve_target(None, Binary.load(str(target))) == (None, None)


# --------------------------------------------------------------------------
# Unit: the profile stage must YIELD to an override rather than overwrite it.
# --------------------------------------------------------------------------

def test_profile_stage_yields_to_the_override(target, addrs):
    """`run_static_analysis` assigns `win_function` unconditionally when it finds
    a match, so an override has to be honoured by that function explicitly. This
    is the test that fails if someone later "simplifies" the override away."""
    from supwngo.core.binary import Binary
    from supwngo.core.context import ExploitContext
    from supwngo.exploit.pipeline.profile_stage import run_static_analysis
    from supwngo.exploit.pipeline.target_overrides import resolve_target

    binary = Binary.load(str(target))

    # Positive control: with no override, detection finds `stage_two` on its own
    # (via WinFunctionFinder's system()-calling scan). Asserted so the negative
    # below cannot pass merely because detection found nothing.
    plain = ExploitContext.from_binary(binary)
    run_static_analysis(plain)
    assert plain.win_function is not None
    assert plain.win_function[1] == addrs["stage_two"]

    # Override to the OTHER function: detection's answer must be discarded.
    override, _ = resolve_target("handle", binary)
    ctx = ExploitContext.from_binary(binary)
    ctx.win_override = override
    run_static_analysis(ctx)
    assert ctx.win_function == ("handle", addrs["handle"])
    assert ctx.win_function[1] != addrs["stage_two"]


def test_rop_without_ret2_is_rejected_loudly(target):
    """An option accepted and silently ignored is the failure class the engine
    constructor already guards for `input_name`/`input_argv`; `--rop` with
    nothing to modify joins them rather than being quietly dropped."""
    from supwngo.core.binary import Binary
    from supwngo.exploit.pipeline.orchestrator import CanonicalAutopwnEngine

    with pytest.raises(ValueError, match="rop"):
        CanonicalAutopwnEngine(Binary.load(str(target)), rop=True)


def test_engine_seeds_win_from_a_plain_ret2_but_not_from_a_rop_gadget(target, addrs):
    """`--ret2 ADDR` doubles as the win target; `--ret2 ADDR --rop` must not.

    This is the entire reason `--rop` exists: a bare address cannot say whether
    it is a place to land or a link in a chain, and feeding a gadget to something
    expecting a function builds a chain that jumps into mid-instruction.
    """
    from supwngo.core.binary import Binary
    from supwngo.exploit.pipeline.orchestrator import CanonicalAutopwnEngine

    binary = Binary.load(str(target))

    plain = CanonicalAutopwnEngine(binary, ret2=hex(addrs["handle"]))
    assert plain.context.win_override is not None
    assert plain.context.win_override.address == addrs["handle"]

    gadget = CanonicalAutopwnEngine(binary, ret2=hex(addrs["handle"]), rop=True)
    assert gadget.context.ret2_override.is_rop_gadget is True
    assert gadget.context.win_override is None, (
        "a --rop gadget must never be promoted to the win/return target"
    )


def test_explicit_win_beats_ret2(target, addrs):
    from supwngo.core.binary import Binary
    from supwngo.exploit.pipeline.orchestrator import CanonicalAutopwnEngine

    engine = CanonicalAutopwnEngine(
        Binary.load(str(target)), win="stage_two", ret2="handle",
    )
    assert engine.context.win_override.address == addrs["stage_two"]
    assert engine.context.ret2_override.address == addrs["handle"]


# --------------------------------------------------------------------------
# End to end: the address in the generated script is the operator's.
# --------------------------------------------------------------------------

@pytest.mark.slow
def test_win_override_redirects_the_payload(target, addrs, tmp_path):
    """The central test. See this module's docstring for why it asserts a
    FAILURE rather than a success."""
    auto_script = tmp_path / "auto.py"
    auto_result, auto_text = _solve(target, auto_script)

    # Baseline: auto-detection targets stage_two and solves.
    assert auto_result is not None and auto_result.get("success") is True
    assert hex(addrs["stage_two"]) in auto_text.lower()

    over_script = tmp_path / "override.py"
    over_result, over_text = _solve(target, over_script, "--win", "handle")

    # (1) the override reached the payload builder
    assert hex(addrs["handle"]) in over_text.lower()
    assert hex(addrs["stage_two"]) not in over_text.lower(), (
        "the detected address is still in the script -- the override did not "
        "replace it"
    )
    # (2) and was not silently undone when it did not pan out. `handle` just
    # re-runs the read loop, so no shell: honouring the operator means failing.
    assert over_result is not None and over_result.get("success") is not True


@pytest.mark.slow
def test_rop_modifier_changes_which_address_is_used(target, addrs, tmp_path):
    """`--ret2 handle` lands on `handle`; adding `--rop` must not.

    Note the deliberate choice of `handle` over `stage_two`: pointed at
    `stage_two`, `--rop` "working" and `--rop` "ignored" produce the SAME
    address, because auto-detection picks `stage_two` too. The first version of
    this check did exactly that and could not have failed.
    """
    dest_script = tmp_path / "dest.py"
    _solve(target, dest_script, "--ret2", "handle")
    assert hex(addrs["handle"]) in dest_script.read_text().lower()

    gadget_script = tmp_path / "gadget.py"
    _solve(target, gadget_script, "--ret2", "handle", "--rop")
    text = gadget_script.read_text().lower()
    assert hex(addrs["stage_two"]) in text, (
        "with --rop the ret2 address must be left out of the win slot, so "
        "auto-detection's address should appear instead"
    )
    assert hex(addrs["handle"]) not in text


@pytest.mark.slow
def test_unresolvable_win_warns_and_still_solves(target, addrs, tmp_path):
    """Warn-and-fall-back, end to end: a typo must cost a warning, not the run.

    This is the behaviour the operator explicitly chose over a hard error, so it
    is pinned here -- a later "tighten this up" change would break a documented
    decision rather than an implementation detail.
    """
    script = tmp_path / "typo.py"
    result, text = _solve(target, script, "--win", "definitely_not_a_symbol_xyz")
    assert result is not None and result.get("success") is True
    assert hex(addrs["stage_two"]) in text.lower()


# --------------------------------------------------------------------------
# `explain` honours the overrides too, and its own scan is the STRICTER one.
# --------------------------------------------------------------------------

def test_explain_facts_honour_the_override(target, addrs):
    """The walkthrough runs its own win scan, which drops flag-named symbols
    outright -- so an override honoured only by `solve` would have `explain`
    teaching a different address than the exploit uses."""
    from supwngo.exploit.walkthrough.facts import collect_facts

    plain = collect_facts(str(target), probe=False)
    over = collect_facts(str(target), probe=False, win="handle")

    assert over.win_functions == [("handle", addrs["handle"])]
    assert plain.win_functions != over.win_functions
    assert any("supplied by operator" in p for p in over.provenance)


def test_explain_ignores_a_rop_gadget_as_a_destination(target, addrs):
    from supwngo.exploit.walkthrough.facts import collect_facts

    facts = collect_facts(str(target), probe=False, ret2="handle", rop=True)
    assert (facts.win_functions or []) != [("handle", addrs["handle"])]
    assert any("chain link" in p for p in facts.provenance)


def test_explain_records_an_ignored_bad_spec(target):
    from supwngo.exploit.walkthrough.facts import collect_facts

    facts = collect_facts(str(target), probe=False, win="not_a_real_symbol_xyz")
    assert any("override IGNORED" in p for p in facts.provenance)
