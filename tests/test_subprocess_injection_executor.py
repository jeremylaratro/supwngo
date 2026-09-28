"""Proofs for the subprocess-injection executor (`subprocess_injection`).

Corpus: benchmark/corpus_inject/ (5 positives + 1 negative control), built with
    SUPWNGO_BENCH_CORPUS=benchmark/corpus_inject benchmark/build_all.sh

Two things here are worth more than the usual "the executor works" coverage,
because both were **measured** during development rather than assumed:

1. **The pipeline's standard shell oracle false-positives on this entire
   category.** `PipelineVerifier.verify_script` writes `echo <token>` to the
   generated script's stdin and credits SHELL_ACCESS when the token comes back on
   stdout. Every target in this category echoes its input by construction, so
   forwarding stdin to an *uncompromised* target makes its own main loop print
   `checking echo <token>` -- token present, no shell anywhere. Measured against
   `inject_90_neg_execv_argv`: the naive check reports a shell.

   The generated script therefore proves a shell with a marker `/bin/echo` cannot
   produce (`id` -> `uid=`) before it bridges stdin. `test_generated_script_*`
   below guard that, and they are written as *presence* assertions on the
   self-test rather than an absence assertion about tokens -- an absence check
   would pass vacuously the moment anything is renamed.

2. **The negative control is protected twice over, and both layers are proven
   separately.** The gate rejects it (no shell-path string beside its `exec*`),
   and forcing it through the full ladder anyway still fails. A control that is
   only ever *skipped* would make the whole measurement vacuous, so
   `test_control_fails_even_when_the_gate_is_bypassed` removes the gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "benchmark" / "corpus_inject"

from supwngo.exploit.pipeline.executors import build_default_registry
from supwngo.exploit.pipeline.executors.subprocess_injection_techniques import (
    SubprocessInjectionExecutor,
    build_ladder,
    find_blocklist,
    find_command_template,
    find_prompt,
    has_decoder,
    shell_sink,
    template_suffix,
)

POSITIVES = (
    "inject_10_system_baseline",
    "inject_11_popen_sink",
    "inject_12_execl_dash_c",
    "inject_13_decode_after_validate",
    "inject_14_suffix_pipeline",
)
CONTROL = "inject_90_neg_execv_argv"


def _binary(slug: str):
    path = CORPUS / slug / slug
    if not path.is_file():
        pytest.skip(f"{path} not built (see this module's docstring)")
    from supwngo.core.binary import Binary

    return Binary.load(str(path))


def _context(slug: str):
    from supwngo.core.context import ExploitContext

    ctx = ExploitContext(arch="amd64", bits=64)
    ctx.binary = _binary(slug)
    return ctx


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_executor_is_registered_in_the_default_registry():
    registry = build_default_registry()
    assert "subprocess_injection" in repr(registry.__dict__)


# --------------------------------------------------------------------------
# Ladder ordering -- the derived part. These need no corpus.
# --------------------------------------------------------------------------


def test_bare_spelling_leads_when_the_template_ends_at_the_substitution():
    ladder = build_ladder(blocklist=None, suffix=b"", decoder=False)
    assert ladder[0] == "x; sh"


def test_terminated_spelling_leads_when_the_template_continues_past_it():
    """A `| /bin/cat -` after the %s steals an injected command's stdout, so the
    payload that comments the remainder out has to be tried first."""
    ladder = build_ladder(blocklist=None, suffix=b"| /bin/cat -", decoder=False)
    assert ladder[0] == "x; sh #"
    # Both spellings still present -- the derivation sets order, not membership.
    assert "x; sh" in ladder


def test_a_blocked_separator_is_demoted_below_the_ones_that_survive():
    ladder = build_ladder(blocklist=b";&|$`", suffix=b"", decoder=False)
    semicolon = next(i for i, r in enumerate(ladder) if r == "x; sh")
    survivor = next(i for i, r in enumerate(ladder) if r == "x\nsh")
    assert survivor < semicolon, (
        "a separator the target rejects must not occupy an earlier rung than one "
        f"it does not; got {ladder}"
    )


def test_encoded_spellings_lead_when_the_target_decodes_after_validating():
    ladder = build_ladder(blocklist=b";&|$`", suffix=b"", decoder=True)
    assert ladder[0] == "x%3bsh"


def test_ladder_ordering_actually_changes_with_the_derived_facts():
    """Positive control for the three tests above: if build_ladder ignored its
    arguments they would all still pass on a fixed list, so prove the orderings
    differ from each other."""
    a = build_ladder(blocklist=None, suffix=b"", decoder=False)
    b = build_ladder(blocklist=None, suffix=b"| /bin/cat -", decoder=False)
    c = build_ladder(blocklist=b";&|$`", suffix=b"", decoder=True)
    assert a != b and b != c and a != c


# --------------------------------------------------------------------------
# Static derivation, measured against the corpus
# --------------------------------------------------------------------------


@pytest.mark.parametrize("slug", POSITIVES)
def test_gate_accepts_every_positive(slug):
    assert SubprocessInjectionExecutor().is_applicable(_context(slug)) is True


def test_gate_rejects_the_execv_argv_control():
    """The one static fact that separates this category's positives from a target
    doing the same job safely: an `exec*` with no shell path beside it."""
    binary = _binary(CONTROL)
    assert shell_sink(binary) is None
    assert SubprocessInjectionExecutor().is_applicable(_context(CONTROL)) is False


def test_gate_rejection_is_not_vacuous():
    """Guard against the control being rejected for an unrelated reason (an
    unreadable image, a missing reader import). It must have the reader and the
    exec call, and lack only the shell path."""
    binary = _binary(CONTROL)
    assert "fgets" in binary.plt or "fgets" in binary.symbols
    assert any(
        n in binary.plt or n in binary.symbols for n in ("execv", "execl", "execve")
    )
    assert b"/bin/sh" not in (CORPUS / CONTROL / CONTROL).read_bytes()


def test_command_template_and_suffix_are_read_off_the_image():
    plain = _binary("inject_10_system_baseline")
    piped = _binary("inject_14_suffix_pipeline")
    assert find_command_template(plain) == b"/bin/echo checking %s"
    assert template_suffix(find_command_template(plain)) == b""
    assert template_suffix(find_command_template(piped)) == b"| /bin/cat -"


def test_reject_set_and_decoder_are_detected_on_the_filtered_target():
    filtered = _binary("inject_13_decode_after_validate")
    unfiltered = _binary("inject_10_system_baseline")
    assert find_blocklist(filtered) == b";&|$`"
    assert has_decoder(filtered) is True
    # Negative side: the unfiltered anchor must NOT report a reject set, or the
    # detector is matching prose rather than a blocklist.
    assert find_blocklist(unfiltered) is None


def test_prompt_is_detected():
    assert find_prompt(_binary("inject_10_system_baseline")) == b"netcheck> "


# --------------------------------------------------------------------------
# The generated script's own shell proof -- see this module's docstring
# --------------------------------------------------------------------------


def _script_for(slug: str) -> str:
    executor = SubprocessInjectionExecutor()
    context = _context(slug)
    binary = context.binary
    return executor._script(
        context,
        shell_sink(binary),
        build_ladder(
            find_blocklist(binary),
            template_suffix(find_command_template(binary)),
            has_decoder(binary),
        ),
        find_prompt(binary),
        find_command_template(binary),
        find_blocklist(binary),
        has_decoder(binary),
    )


def test_generated_script_proves_the_shell_with_a_marker_echo_cannot_produce():
    script = _script_for("inject_10_system_baseline")
    assert 'SHELL_MARK = b"uid="' in script
    assert 'SHELL_TEST = b"id"' in script
    assert "if SHELL_MARK in seen:" in script


def test_generated_script_bridges_stdin_only_after_the_ladder_confirms():
    """Ordering is the whole safety property: bridge() forwards the verifier's
    `echo <token>` stdin, so it must be unreachable until probe() has proven a
    shell. Asserted on the call order in the emitted body."""
    script = _script_for("inject_10_system_baseline")
    assert "def bridge(io, seen):" in script  # subject exists, so the check below is real
    # Anchor on the 4-space-indented exploit() body, not on bare substrings: the
    # names also appear in the module-level `def`s above, and matching those made
    # an earlier version of this test compare a definition against a call.
    ladder_call = script.index("\n    io, seen = run_ladder()")
    bridge_call = script.index("\n    bridge(io, seen)")
    assert ladder_call < bridge_call


def test_generated_script_records_the_derivations_it_used():
    """The script is the artifact a user is handed; it has to say why it chose
    these payloads, not just carry them."""
    script = _script_for("inject_13_decode_after_validate")
    assert "Reject set:" in script
    assert ";&|$`" in script
    assert "x%3bsh" in script
