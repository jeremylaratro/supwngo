"""Tests for the walkthrough families and route selection.

The model tests (``test_walkthrough_model.py``) prove a stub cannot be
*expressed*.  These prove the families do not *author* one: that every shipped
family renders to valid, self-consistent Python; that route selection is driven
by measured protections rather than preference; and that the content is
binary-specific rather than a filled-in template.

Most tests build :class:`TargetFacts` by hand so they are hermetic and fast --
no corpus binary, no subprocess, no pwntools ROP scan.  The handful that need a
real ELF are gated on the corpus being built and skip cleanly otherwise.

Covers `docs/plans/2026-09-23-walkthrough-engine.md`.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from supwngo.exploit.walkthrough.facts import (
    GadgetFact,
    MeasuredOffset,
    ProtectionFacts,
    TargetFacts,
)
from supwngo.exploit.walkthrough.model import Confidence, Evidence
from supwngo.exploit.walkthrough.registry import (
    generate_walkthrough,
    propose_routes,
)
from supwngo.exploit.walkthrough.render import render_markdown, render_script

CORPUS = Path(__file__).resolve().parent.parent / "benchmark" / "corpus"

#: Targets the generated walkthroughs were validated against by hand, as
#: ``(directory, binary-name)``.  Kept small deliberately: these are the three
#: whose walkthroughs were followed literally, step by step, to a flag.
VALIDATED_TARGETS = [
    ("01_shellcode_stack", "shellcode_stack"),
    ("02_ret2plt_system", "ret2plt_system"),
    ("07_ret2libc_leak", "ret2libc_leak"),
    ("09_srop", "srop"),
    ("15_win_function", "win_function"),
]

#: The route each validated target must select, so a scoring change that
#: silently reroutes a target fails here rather than in someone's terminal.
EXPECTED_ROUTES = {
    "shellcode_stack": ("stack_bof", "ret2shellcode"),
    "ret2plt_system": ("rop_chain", "ret2plt"),
    "ret2libc_leak": ("rop_chain", "ret2libc"),
    "srop": ("syscall", "SROP"),
    "win_function": ("stack_bof", "ret2win"),
}


# ---------------------------------------------------------------------------
# synthetic fact builders
# ---------------------------------------------------------------------------


def measured_offset(value=72):
    return MeasuredOffset(
        value=value,
        confidence=Confidence.MEASURED,
        evidence=Evidence(
            method="cyclic pattern, faulted return address read under gdb",
            command="gdb -q -batch -ex 'run < /tmp/pattern' -ex 'x/1gx $rsp' ./vuln",
        ),
    )


def gadget(slug, address, instructions, **kw):
    return GadgetFact(slug=slug, address=address, instructions=instructions, **kw)


# The families hash the binary (so a reader can tell whether the walkthrough
# matches the file in front of them), so ``path`` has to point at something
# real even for hand-built facts.  Content is irrelevant; only that it exists
# and is stable for the session.
_FIXTURE_DIR = tempfile.mkdtemp(prefix="supwngo-wt-tests-")
_FIXTURE_BINARY = Path(_FIXTURE_DIR) / "vuln"
_FIXTURE_BINARY.write_bytes(b"\x7fELF not-a-real-binary, only its sha256 is used\n")


def base_facts(**overrides) -> TargetFacts:
    """Facts for a plain NX-on, no-PIE, no-canary stack overflow."""
    kwargs: dict = dict(
        path=str(_FIXTURE_BINARY),
        protections=ProtectionFacts(
            nx=True, pie=False, canary=False, relro="Partial RELRO"
        ),
        symbols={"main": 0x401196, "vuln": 0x401176},
        func_symbols={"main": 0x401196, "vuln": 0x401176},
        vuln_function="vuln",
        offset=measured_offset(),
        prompts=[b"Input: "],
        provenance=["hand-built TargetFacts (test fixture)"],
    )
    kwargs.update(overrides)
    return TargetFacts(**kwargs)


def ret2plt_facts(**overrides) -> TargetFacts:
    kwargs: dict = dict(
        plt={"system": 0x401060, "puts": 0x401050},
        got={"puts": 0x404018},
        binsh=0x402008,
        gadgets={
            "ret": gadget("ret", 0x40101A, "ret"),
            "pop_rdi": gadget(
                "pop_rdi",
                0x4011FA,
                "pop rdi; ret",
                symbol_note=(
                    "gadget_pop_rdi_ret+4 (the symbol itself is 0x4011f6; the "
                    "first 4 bytes are an endbr64 CET landing pad)"
                ),
            ),
        },
    )
    kwargs.update(overrides)
    return base_facts(**kwargs)


def ret2libc_facts(**overrides) -> TargetFacts:
    kwargs: dict = dict(
        plt={"puts": 0x401050, "printf": 0x401060},
        got={"puts": 0x404018, "printf": 0x404020},
        gadgets={
            "ret": gadget("ret", 0x40101A, "ret"),
            "pop_rdi": gadget("pop_rdi", 0x4011FA, "pop rdi; ret"),
        },
        libc_path="/usr/lib/x86_64-linux-gnu/libc.so.6",
        vuln_reentry_count=2,
    )
    kwargs.update(overrides)
    return base_facts(**kwargs)


def srop_facts(**overrides) -> TargetFacts:
    """Static binary with pop rax + syscall but no argument-register gadgets."""
    kwargs: dict = dict(
        protections=ProtectionFacts(
            nx=True, pie=False, canary=False, relro="Partial RELRO", static=True
        ),
        binsh=0x4A1234,
        gadgets={
            "ret": gadget("ret", 0x40101A, "ret"),
            "pop_rax": gadget("pop_rax", 0x4017F4, "pop rax; ret"),
            "syscall": gadget("syscall", 0x401234, "syscall"),
        },
    )
    kwargs.update(overrides)
    return base_facts(**kwargs)


def ret2syscall_facts(**overrides) -> TargetFacts:
    kwargs: dict = dict(
        gadgets={
            "ret": gadget("ret", 0x40101A, "ret"),
            "pop_rax": gadget("pop_rax", 0x4017F4, "pop rax; ret"),
            "pop_rdi": gadget("pop_rdi", 0x4011FA, "pop rdi; ret"),
            "pop_rsi": gadget("pop_rsi", 0x401200, "pop rsi; ret"),
            "pop_rdx": gadget("pop_rdx", 0x401206, "pop rdx; ret"),
            "syscall": gadget("syscall", 0x401234, "syscall"),
        },
        binsh=0x4A1234,
        protections=ProtectionFacts(
            nx=True, pie=False, canary=False, relro="Partial RELRO", static=True
        ),
    )
    kwargs.update(overrides)
    return base_facts(**kwargs)


def shellcode_facts(**overrides) -> TargetFacts:
    kwargs: dict = dict(
        protections=ProtectionFacts(
            nx=False, pie=False, canary=False, relro="Partial RELRO"
        ),
    )
    kwargs.update(overrides)
    return base_facts(**kwargs)


def ret2win_facts(**overrides) -> TargetFacts:
    kwargs: dict = dict(
        symbols={"main": 0x401196, "vuln": 0x401176, "win": 0x401146},
        func_symbols={"main": 0x401196, "vuln": 0x401176, "win": 0x401146},
        win_functions=[("win", 0x401146)],
    )
    kwargs.update(overrides)
    return base_facts(**kwargs)


ALL_FIXTURES = {
    "ret2plt": (ret2plt_facts, "rop_chain"),
    "ret2libc": (ret2libc_facts, "rop_chain"),
    "srop": (srop_facts, "syscall"),
    "ret2syscall": (ret2syscall_facts, "syscall"),
    "ret2shellcode": (shellcode_facts, "stack_bof"),
    "ret2win": (ret2win_facts, "stack_bof"),
    "nothing": (base_facts, "triage"),
}


# ---------------------------------------------------------------------------
# route selection is driven by measured protections
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture_name", sorted(ALL_FIXTURES), ids=sorted(ALL_FIXTURES)
)
def test_expected_family_wins(fixture_name):
    """The facts, not a preference order, decide which family authors."""
    build_facts, expected_family = ALL_FIXTURES[fixture_name]
    wt = generate_walkthrough(build_facts())
    assert wt.family == expected_family


def test_nx_off_makes_shellcode_viable_again():
    """NX is the gate on shellcode, and nothing else is.

    It does not follow that shellcode then *wins*: ret2plt beats it when
    system@plt is present, because a one-gadget call into an existing PLT entry
    has fewer moving parts than staging bytes at an address you must first
    learn.  What must hold is that shellcode stops being ruled out.
    """
    facts = ret2plt_facts(
        protections=ProtectionFacts(
            nx=False, pie=False, canary=False, relro="Partial RELRO"
        )
    )
    wt = generate_walkthrough(facts)
    shellcode = [r for r in wt.routes if "shellcode" in r.name.lower()]
    assert shellcode, "with NX off, shellcode must appear in the decision tree"
    assert shellcode[0].applicable

    # And with no system@plt to return into, it is what the reader is taught.
    bare = generate_walkthrough(shellcode_facts())
    assert bare.family == "stack_bof"
    assert "shellcode" in bare.primary_route.name.lower()


def test_nx_on_rules_out_shellcode_in_the_decision_tree():
    """NX-on must not merely lose -- it must be recorded as ruled out, with
    the condition that would bring it back."""
    wt = generate_walkthrough(ret2plt_facts())
    shellcode = [r for r in wt.routes if "shellcode" in r.name.lower()]
    if shellcode:  # the family may abstain entirely, which is also honest
        assert not shellcode[0].applicable
        assert shellcode[0].becomes_viable_if


def test_no_argument_gadgets_selects_srop_not_ret2syscall():
    """SROP exists precisely to avoid needing pop rdi/rsi/rdx."""
    wt = generate_walkthrough(srop_facts())
    assert "SROP" in wt.primary_route.name


def test_argument_gadgets_present_selects_ret2syscall():
    wt = generate_walkthrough(ret2syscall_facts())
    assert "ret2syscall" in wt.primary_route.name


def test_system_plt_present_prefers_ret2plt_over_leaking():
    """A leak you do not need is a step that can fail for nothing."""
    wt = generate_walkthrough(ret2plt_facts())
    assert "ret2plt" in wt.primary_route.name


def test_no_system_plt_falls_back_to_a_got_leak():
    wt = generate_walkthrough(ret2libc_facts())
    assert "ret2libc" in wt.primary_route.name


def test_full_relro_is_recorded_as_a_protection_verdict():
    facts = ret2plt_facts(
        protections=ProtectionFacts(
            nx=True, pie=False, canary=False, relro="Full RELRO"
        )
    )
    wt = generate_walkthrough(facts)
    relro = [p for p in wt.protections if "relro" in p.name.lower()]
    assert relro, "Full RELRO must appear in the protections section"
    assert relro[0].rules_out, "Full RELRO must name what it rules out (GOT overwrite)"


def test_forcing_a_family_names_that_route_in_the_header():
    """`explain --family triage` must not print the best-scoring route.

    Telling the reader they are reading a ret2plt walkthrough while the steps
    do guided triage is worse than no header at all.
    """
    facts = ret2plt_facts()
    wt = generate_walkthrough(facts, family="triage")
    assert wt.family == "triage"
    assert wt.taught_route
    assert wt.primary_route.name == wt.taught_route
    assert "triage" in wt.primary_route.name.lower()


def test_forcing_an_abstaining_family_raises_rather_than_inventing():
    with pytest.raises(ValueError, match="No family named"):
        generate_walkthrough(base_facts(), family="no_such_family")


def test_every_family_declares_its_taught_route():
    """Guards against a new family forgetting it, which silently reintroduces
    the mislabelled-header bug."""
    for name, (build_facts, _expected) in sorted(ALL_FIXTURES.items()):
        wt = generate_walkthrough(build_facts())
        assert wt.taught_route, f"{name}: no taught_route declared"
        assert wt.taught_route in {r.name for r in wt.routes}


# ---------------------------------------------------------------------------
# every family renders to a runnable artifact
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture_name", sorted(ALL_FIXTURES), ids=sorted(ALL_FIXTURES)
)
def test_rendered_script_compiles(fixture_name):
    """render_script() compiles its own output, so this also asserts it did
    not silently stop doing that."""
    build_facts, _ = ALL_FIXTURES[fixture_name]
    text = render_script(generate_walkthrough(build_facts()))
    compile(text, f"<{fixture_name}>", "exec")


@pytest.mark.parametrize(
    "fixture_name", sorted(ALL_FIXTURES), ids=sorted(ALL_FIXTURES)
)
def test_rendered_script_has_no_placeholder_stub(fixture_name):
    """The exact artifact this feature exists to replace."""
    build_facts, _ = ALL_FIXTURES[fixture_name]
    text = render_script(generate_walkthrough(build_facts()))
    assert "TODO" not in text
    assert "FIXME" not in text
    assert "offset = 0" not in text
    assert "XXX" not in text


@pytest.mark.parametrize(
    "fixture_name", sorted(ALL_FIXTURES), ids=sorted(ALL_FIXTURES)
)
def test_every_step_is_individually_runnable(fixture_name):
    """A step the reader cannot run on its own is not a step, it is prose.

    The rendered dispatcher must know every step by number *and* by name.
    """
    build_facts, _ = ALL_FIXTURES[fixture_name]
    wt = generate_walkthrough(build_facts())
    text = render_script(wt)
    for step in wt.steps:
        assert f'"{step.id}"' in text, f"step {step.id} not reachable by name"


@pytest.mark.parametrize(
    "fixture_name", sorted(ALL_FIXTURES), ids=sorted(ALL_FIXTURES)
)
def test_every_step_states_expectation_and_verification(fixture_name):
    build_facts, _ = ALL_FIXTURES[fixture_name]
    wt = generate_walkthrough(build_facts())
    for step in wt.steps:
        assert step.why.strip(), f"{step.id}: no WHY"
        assert step.expect.strip(), f"{step.id}: no EXPECT"
        assert step.verify.strip(), f"{step.id}: no VERIFY"
        assert step.on_failure, f"{step.id}: no troubleshooting"


@pytest.mark.parametrize(
    "fixture_name", sorted(ALL_FIXTURES), ids=sorted(ALL_FIXTURES)
)
def test_walkthroughs_end_in_an_assembled_exploit(fixture_name):
    build_facts, _ = ALL_FIXTURES[fixture_name]
    wt = generate_walkthrough(build_facts())
    assert wt.final_exploit.strip(), "no assembled exploit"
    assert wt.success_criteria.strip(), "no machine-checkable success criteria"


@pytest.mark.parametrize(
    "fixture_name", sorted(ALL_FIXTURES), ids=sorted(ALL_FIXTURES)
)
def test_markdown_render_also_works(fixture_name):
    build_facts, _ = ALL_FIXTURES[fixture_name]
    text = render_markdown(generate_walkthrough(build_facts()))
    assert text.startswith("#")
    assert "TODO" not in text


@pytest.mark.parametrize(
    "fixture_name", sorted(ALL_FIXTURES), ids=sorted(ALL_FIXTURES)
)
def test_manual_tooling_is_taught(fixture_name):
    """The interactive tools are part of the teaching, not an appendix."""
    build_facts, _ = ALL_FIXTURES[fixture_name]
    text = render_script(generate_walkthrough(build_facts()))
    assert "checksec" in text
    assert "gdb" in text.lower()


# ---------------------------------------------------------------------------
# honest degradation
# ---------------------------------------------------------------------------


def test_unknown_offset_is_named_not_faked():
    facts = base_facts(
        offset=MeasuredOffset(
            value=None,
            confidence=Confidence.UNKNOWN,
            evidence=Evidence(method="dynamic cyclic probe", detail="target did not fault"),
            plausible="16 or 24 or 32 or 40",
            failure_reason="the dynamic cyclic probe did not produce a usable fault value",
        )
    )
    wt = generate_walkthrough(facts)
    unknowns = [f for f in wt.all_facts() if f.confidence is Confidence.UNKNOWN]
    assert unknowns, "an unmeasured offset must surface as UNKNOWN"
    offset = next(f for f in unknowns if f.name == "OFFSET")
    assert offset.unknown_reason, "an UNKNOWN must say why"
    assert offset.plausible, "an UNKNOWN must give a plausible range"
    assert offset.resolved_by, "an UNKNOWN must name the step that resolves it"

    text = render_script(wt)
    assert "offset = 0" not in text
    # The assembled exploit must refuse to run rather than use a fake value.
    assert "_unknown(" in text


def test_no_route_still_produces_the_discovery_workflow():
    """A walkthrough that says "I don't know" and stops is the stub again."""
    wt = generate_walkthrough(base_facts())
    assert wt.family == "triage"
    assert len(wt.steps) >= 3
    text = render_script(wt)
    compile(text, "<triage>", "exec")


def test_automation_failure_context_is_carried_into_the_header():
    class FakeHandoff:
        summary = "ret2win: FAILED at DELIVERY; ret2libc: SKIPPED"

    facts = base_facts(
        handoff=FakeHandoff(),
        automation_failure="ret2win: FAILED at DELIVERY; ret2libc: SKIPPED",
    )
    text = render_script(generate_walkthrough(facts))
    assert "AUTOMATION FAILED" in text
    assert "FAILED at DELIVERY" in text


# ---------------------------------------------------------------------------
# the traps that fail silently
# ---------------------------------------------------------------------------


def test_gadget_symbol_discrepancy_is_taught_not_hidden():
    """Using the symbol address instead of the gadget address does not crash;
    it just does the wrong thing, indistinguishable from a bad technique
    choice.  So the discrepancy has to be in the text."""
    text = render_script(generate_walkthrough(ret2plt_facts()))
    assert "endbr64" in text
    assert "0x4011fa" in text.lower()


def test_movaps_alignment_trap_is_explained_on_the_ret2plt_route():
    text = render_script(generate_walkthrough(ret2plt_facts()))
    assert "movaps" in text


def test_binsh_is_searched_as_bytes_not_taken_from_a_symbol():
    """`const char *g_shell_cmd = "/bin/sh"` is a pointer, not the string."""
    text = render_script(generate_walkthrough(ret2plt_facts()))
    assert "search(" in text


def test_libc_is_derived_on_the_readers_machine():
    """A libc path measured here is wrong there.  The walkthrough must derive
    it, with the measured path demoted to a documented fallback."""
    text = render_script(generate_walkthrough(ret2libc_facts()))
    assert "libc_elf()" in text
    assert "LIBC_OVERRIDE" in text
    assert ".libc" in text


def test_leak_validation_does_not_test_the_leading_byte():
    """Whether a libc address starts 0x7f depends on vm.mmap_rnd_bits.

    A check that rejects correct leaks is worse than no check, so the leak
    validation must test a range and page alignment -- invariants -- and the
    prose must warn the reader off the leading byte instead of quietly relying
    on it.  Mentioning 0x7f to say "do not test this" is the point; what must
    not exist is an executable comparison against it.
    """
    text = render_script(generate_walkthrough(ret2libc_facts()))
    assert "1 << 40" in text or "2**40" in text
    assert "vm.mmap_rnd_bits" in text, "the reason must be cited, not asserted"

    code_lines = [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    for line in code_lines:
        assert ">> 40" not in line or "0x7f" not in line, (
            "leading-byte comparison in executable code: " + line
        )
        assert "0x7f0000000000" not in line


def test_flag_extraction_is_never_a_route_or_a_success_criterion():
    """The prohibition is on flag *extraction as a route*.

    Reading the flag from a shell you earned is the endgame of the exercise, so
    an interactive hint may mention it.  What must never happen: a static scan
    presented as a way in, or a walkthrough that scores itself on having found
    a flag string.  Success is always the `PWNED_42` echo, which only a real
    shell can produce.
    """
    for name, (build_facts, _) in sorted(ALL_FIXTURES.items()):
        wt = generate_walkthrough(build_facts())
        text = render_script(wt)
        lowered = text.lower()

        assert "flag" not in wt.success_criteria.lower(), (
            f"{name}: scores itself on a flag rather than on a shell"
        )
        # `strings` is legitimate recon for symbols and /bin/sh; it must never
        # be aimed at a flag *in executable code*. Prose is allowed to name the
        # anti-pattern in order to warn against it, and triage does exactly
        # that -- so only the code is scanned here.
        code = "\n".join(
            line
            for line in lowered.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        for chunk in code.split("strings")[1:]:
            assert "flag" not in chunk[:200], f"{name}: strings aimed at a flag"
        # No step may *read* or *locate* a flag. The one permitted mention is a
        # log line telling the operator what to type into a shell they have
        # already confirmed -- that is the endgame of the exercise, not a
        # shortcut past it. So a flag may appear only inside a log call, never
        # in an open()/read()/search()/subprocess. Comments are exempt too:
        # triage's recon step explains why it deliberately does not look for
        # one, and that explanation is worth having.
        for step in wt.steps:
            for line in step.code.lower().splitlines():
                stripped = line.strip()
                if "flag" not in stripped or stripped.startswith("#"):
                    continue
                assert stripped.startswith("log."), (
                    f"{name}/{step.id}: flag mentioned outside a log line: {line}"
                )
                for forbidden in ("open(", "read(", "search(", "subprocess", "recv"):
                    assert forbidden not in stripped, (
                        f"{name}/{step.id}: step reads a flag: {line}"
                    )


# ---------------------------------------------------------------------------
# content is binary-specific, not a filled-in template
# ---------------------------------------------------------------------------


def test_strategies_differ_across_fixtures():
    """If two different binaries get the same prose, the prose is filler."""
    strategies = {}
    for name, (build_facts, _) in sorted(ALL_FIXTURES.items()):
        wt = generate_walkthrough(build_facts())
        strategies[name] = wt.strategy.strip()
    assert len(set(strategies.values())) == len(strategies), (
        "two fixtures produced identical strategy prose: " + repr(strategies)
    )


def test_measured_values_appear_verbatim_in_the_output():
    facts = ret2plt_facts()
    text = render_script(generate_walkthrough(facts))
    assert "72" in text, "the measured offset must appear as a real number"
    assert "0x402008" in text.lower(), "the measured /bin/sh address must appear"


def test_every_constant_carries_provenance():
    for name, (build_facts, _) in sorted(ALL_FIXTURES.items()):
        wt = generate_walkthrough(build_facts())
        for fact in wt.all_facts():
            if fact.confidence is Confidence.UNKNOWN:
                continue
            assert fact.evidence is not None, f"{name}/{fact.name}: no evidence"
            assert fact.evidence.method.strip(), f"{name}/{fact.name}: empty method"


# ---------------------------------------------------------------------------
# real corpus binaries
# ---------------------------------------------------------------------------


def _corpus_binary(directory, name):
    path = CORPUS / directory / name
    if not path.exists():
        pytest.skip(f"benchmark corpus not built: {path}")
    return path


@pytest.mark.parametrize(
    "directory,name", VALIDATED_TARGETS, ids=[d for d, _ in VALIDATED_TARGETS]
)
def test_validated_corpus_targets_render(directory, name):
    """End-to-end on the three targets whose walkthroughs were followed by
    hand to a flag.  Does not run the exploit -- that is the benchmark's job
    -- but does assert the artifact is valid and route selection is stable."""
    from supwngo.exploit.walkthrough.registry import walkthrough_for_binary

    path = _corpus_binary(directory, name)
    wt = walkthrough_for_binary(str(path), probe=False)
    text = render_script(wt)
    compile(text, f"<{name}>", "exec")
    assert "TODO" not in text
    assert wt.taught_route

    expected_family, expected_route = EXPECTED_ROUTES[name]
    assert wt.family == expected_family
    assert expected_route in wt.taught_route


def test_win_functions_are_found_via_stt_func():
    """Regression guard: ``Symbol.type`` is ``"STT_FUNC"``, not ``"FUNC"``.

    Matching only the short spelling left ``func_symbols`` permanently empty,
    which meant no win function was ever detected and every ret2win target fell
    through to guided triage -- a whole route disabled, with no error anywhere.
    """
    from supwngo.exploit.walkthrough.facts import collect_facts

    path = _corpus_binary("15_win_function", "win_function")
    facts = collect_facts(str(path), probe=False)
    assert facts.func_symbols, "func_symbols is empty; the type filter is wrong"
    assert "win" in facts.func_symbols
    assert facts.win_functions, "win() was not recognised as a win function"
    assert any(n == "win" for n, _ in facts.win_functions)

    # And data symbols must stay out: `const char *g_shell_cmd = "/bin/sh"`
    # looks like a backdoor function and is a pointer.
    from supwngo.core.binary import Binary

    binary = Binary.load(str(path))
    for sym_name, sym in (binary.symbols or {}).items():
        if getattr(sym, "type", "") == "STT_OBJECT":
            assert sym_name not in facts.func_symbols


def test_no_two_corpus_targets_share_their_reasoning():
    """The cross-target difference test.

    Generic filler is easiest to detect by generating several real targets and
    checking the explanatory prose is not reused between them.
    """
    from supwngo.exploit.walkthrough.registry import walkthrough_for_binary

    seen_strategy: dict[str, str] = {}
    seen_steps: dict[str, tuple[str, ...]] = {}
    seen_values: dict[str, frozenset] = {}
    for directory, name in VALIDATED_TARGETS:
        path = _corpus_binary(directory, name)
        wt = walkthrough_for_binary(str(path), probe=False)
        seen_strategy[name] = wt.strategy.strip()
        seen_steps[name] = tuple(s.title for s in wt.steps)
        seen_values[name] = frozenset(
            (f.name, repr(f.value))
            for f in wt.all_facts()
            if f.confidence is not Confidence.UNKNOWN
        )

    assert len(set(seen_strategy.values())) == len(seen_strategy), (
        "two corpus targets produced identical strategy prose"
    )
    assert len(set(seen_steps.values())) == len(seen_steps), (
        "two corpus targets produced identical step lists"
    )
    assert len(set(seen_values.values())) == len(seen_values), (
        "two corpus targets produced identical constants -- the values are not "
        "coming from the binaries"
    )

    # Protection *implications* deliberately do repeat: NX means the same thing
    # on every binary, and paraphrasing it per target to look bespoke would be
    # worse writing, not better. These three corpus targets happen to share an
    # identical protection profile (NX on, no canary, no PIE, Partial RELRO),
    # so the differentiation has to live in the facts and the route -- which is
    # what the assertions above check.


def test_propose_routes_is_side_effect_free():
    """Selection must be able to run twice with the same answer; families that
    mutate facts would make the decision tree depend on call order."""
    facts = ret2plt_facts()
    first = [(f.NAME, r.name, r.score) for f, r in propose_routes(facts)]
    second = [(f.NAME, r.name, r.score) for f, r in propose_routes(facts)]
    assert first == second
