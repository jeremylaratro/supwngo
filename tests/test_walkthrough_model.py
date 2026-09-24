"""Tests for the walkthrough data model.

These tests are the guarantee that the artifact this feature exists to replace
-- a stub containing ``offset = 0  # TODO: Find correct offset`` -- cannot be
expressed by the model at all.  Most of them assert that invalid walkthroughs
*raise*, because the value here is in what the model refuses to build.

Covers `docs/plans/2026-09-23-walkthrough-engine.md`.
"""

import pytest

from supwngo.exploit.walkthrough.model import (
    RESERVED_FACT_NAMES,
    Confidence,
    Evidence,
    Fact,
    Fallback,
    ManualCommand,
    ProtectionVerdict,
    Rejection,
    Requirement,
    Route,
    Step,
    Walkthrough,
    WalkthroughError,
    comment_block,
    dedent_code,
)


def make_fact(name="OFFSET", value=72, **kw):
    kw.setdefault(
        "evidence", Evidence(method="cyclic_find on corefile RSP", command="x/gx $rsp")
    )
    kw.setdefault("confidence", Confidence.MEASURED)
    return Fact(name=name, value=value, **kw)


def make_step(step_id="offset", **kw):
    kw.setdefault("title", "Find the buffer-to-return-address offset")
    kw.setdefault("why", "Every later step needs to know where the return address is.")
    kw.setdefault("code", "print(cyclic_find(0x6161616c))")
    kw.setdefault("expect", "The process dies with SIGSEGV and RSP holds 0x6161616c.")
    kw.setdefault("verify", "cyclic_find returns 72, a multiple of 8.")
    return Step(id=step_id, **kw)


def make_route(name="ret2plt/system", score=0.9, applicable=True, **kw):
    kw.setdefault("rationale", "system@plt and a /bin/sh string are both present.")
    if not applicable:
        kw.setdefault("rejection", Rejection.STRUCTURAL)
    return Route(name=name, score=score, applicable=applicable, **kw)


def make_walkthrough(**kw):
    kw.setdefault("binary_path", "/tmp/vuln")
    kw.setdefault("family", "rop_chain")
    kw.setdefault("title", "ret2plt/system on vuln")
    kw.setdefault("strategy", "NX is on so we ROP into system@plt.")
    kw.setdefault("success_criteria", "`echo PWNED_42` echoes back from a shell.")
    kw.setdefault("routes", (make_route(),))
    kw.setdefault("steps", (make_step(),))
    kw.setdefault("final_exploit", "p = process(BINARY); p.send(payload)")
    return Walkthrough(**kw)


class TestFactEvidence:
    def test_known_fact_renders_annotated_assignment(self):
        fact = make_fact(description="Bytes from buf start to the saved return address")
        rendered = fact.render_assignment()
        assert "OFFSET = 72" in rendered
        assert "measured" in rendered
        # Every non-code line must be commented or the script will not parse.
        for line in rendered.splitlines():
            assert line.startswith("#") or line.startswith("OFFSET =")
        # The evidence -- how the value was obtained -- must survive into the
        # generated script, otherwise the reader cannot re-derive it.
        assert "cyclic_find on corefile RSP" in rendered
        assert "x/gx $rsp" in rendered
        assert "Bytes from buf start" in rendered

    def test_addr_kind_renders_hex(self):
        fact = make_fact(name="POP_RDI", value=0x4011FA, kind="addr")
        assert "POP_RDI = 0x4011fa" in fact.render_assignment()

    def test_raw_kind_emits_source_verbatim(self):
        fact = make_fact(name="FRAME", value="SigreturnFrame()", kind="raw")
        assert "FRAME = SigreturnFrame()" in fact.render_assignment()

    def test_bytes_kind_renders_literal(self):
        fact = make_fact(name="BINSH", value=b"/bin/sh\x00", kind="bytes")
        assert "BINSH = b'/bin/sh\\x00'" in fact.render_assignment()

    def test_confidence_is_recorded_so_reader_can_judge(self):
        for confidence in (Confidence.MEASURED, Confidence.DERIVED, Confidence.ASSUMED):
            fact = make_fact(confidence=confidence)
            assert confidence.value in fact.render_assignment()

    def test_non_identifier_name_rejected(self):
        # Facts render as assignments; a non-identifier would emit broken source.
        with pytest.raises(WalkthroughError, match="valid Python identifier"):
            Fact(name="pop rdi", value=1)

    def test_known_confidence_without_value_rejected(self):
        with pytest.raises(WalkthroughError, match="no value"):
            Fact(name="OFFSET", value=None, confidence=Confidence.MEASURED)

    def test_literal_on_unknown_raises(self):
        fact = Fact(
            name="OFFSET",
            confidence=Confidence.UNKNOWN,
            unknown_reason="bisection was inconclusive.",
            plausible="72 or 88",
            resolved_by="offset",
        )
        with pytest.raises(WalkthroughError, match="UNKNOWN"):
            fact.literal()


class TestUnknownMustBeActionable:
    """The core anti-``offset = 0  # TODO`` invariant."""

    @pytest.mark.parametrize(
        "omit", ["unknown_reason", "plausible", "resolved_by"]
    )
    def test_unknown_missing_any_resolution_detail_is_rejected(self, omit):
        kwargs = {
            "unknown_reason": "offset bisection was inconclusive.",
            "plausible": "72 or 88",
            "resolved_by": "offset",
        }
        kwargs.pop(omit)
        with pytest.raises(WalkthroughError, match=omit):
            Fact(name="OFFSET", confidence=Confidence.UNKNOWN, **kwargs)

    def test_well_formed_unknown_renders_actionable_guidance(self):
        fact = Fact(
            name="OFFSET",
            confidence=Confidence.UNKNOWN,
            unknown_reason="the cyclic probe produced no corefile.",
            plausible="72 or 88 (buf is 64 bytes + saved rbp)",
            resolved_by="offset",
        )
        rendered = fact.render_assignment()
        # It must say what is unknown, the plausible range, and which step
        # resolves it -- the useful shape. And it must NOT invent a value.
        assert "no corefile" in rendered
        assert "72 or 88" in rendered
        assert "step 'offset'" in rendered
        assert "_unknown(" in rendered
        assert "OFFSET = 0" not in rendered

    def test_unknown_is_not_known(self):
        fact = Fact(
            name="LIBC_BASE",
            confidence=Confidence.UNKNOWN,
            unknown_reason="ASLR randomises it per run; it must be leaked.",
            plausible="a 0x7f-prefixed page-aligned address",
            resolved_by="offset",
        )
        assert not fact.is_known
        assert make_fact().is_known


class TestStepContract:
    @pytest.mark.parametrize("field", ["title", "why", "code", "expect", "verify"])
    def test_step_requires_every_teaching_field(self, field):
        with pytest.raises(WalkthroughError, match=field):
            make_step(**{field: "   "})

    def test_step_carries_troubleshooting_and_manual_commands(self):
        step = make_step(
            on_failure=(
                Fallback(
                    symptom="process exits cleanly, no SIGSEGV",
                    likely_cause="the pattern never reached the return address",
                    remedy="raise the cyclic length and re-run",
                ),
            ),
            manual=(
                ManualCommand(
                    purpose="confirm protections yourself",
                    command="checksec --file=./vuln",
                    expect="NX enabled, No PIE, No canary",
                ),
            ),
        )
        assert step.on_failure[0].symptom.startswith("process exits cleanly")
        assert step.manual[0].command == "checksec --file=./vuln"
        assert step.function_name == "step_offset"

    def test_sequences_are_normalised_to_tuples(self):
        step = make_step(produces=[make_fact()], consumes=["BINARY"])
        assert isinstance(step.produces, tuple)
        assert isinstance(step.consumes, tuple)


class TestWalkthroughInvariants:
    def test_minimal_walkthrough_is_valid(self):
        wt = make_walkthrough()
        assert wt.number_of("offset") == 1
        assert wt.step("offset").title.startswith("Find the buffer")

    def test_no_steps_rejected(self):
        with pytest.raises(WalkthroughError, match="at least one step"):
            make_walkthrough(steps=())

    def test_missing_final_exploit_rejected(self):
        # "Ends in a complete, assembled, working exploit -- not just fragments."
        with pytest.raises(WalkthroughError, match="complete assembled exploit"):
            make_walkthrough(final_exploit="  ")

    def test_duplicate_step_ids_rejected(self):
        with pytest.raises(WalkthroughError, match="Duplicate step id"):
            make_walkthrough(steps=(make_step(), make_step()))

    def test_duplicate_fact_names_rejected(self):
        steps = (
            make_step("offset", produces=(make_fact(),)),
            make_step("chain", produces=(make_fact(),)),
        )
        with pytest.raises(WalkthroughError, match="Duplicate fact name"):
            make_walkthrough(steps=steps)

    def test_forward_reference_rejected(self):
        # A step consuming a fact that no earlier step provides cannot be
        # followed in order -- the reader would dead-end.
        steps = (
            make_step("chain", consumes=("OFFSET",)),
            make_step("offset", produces=(make_fact(),)),
        )
        with pytest.raises(WalkthroughError, match="consumes 'OFFSET'"):
            make_walkthrough(steps=steps)

    def test_backward_reference_accepted(self):
        steps = (
            make_step("offset", produces=(make_fact(),)),
            make_step("chain", consumes=("OFFSET",)),
        )
        wt = make_walkthrough(steps=steps)
        assert wt.number_of("chain") == 2

    def test_constants_satisfy_consumes(self):
        wt = make_walkthrough(
            constants=(make_fact(name="BINARY", value="/tmp/vuln", kind="str"),),
            steps=(make_step("offset", consumes=("BINARY",)),),
        )
        assert wt.fact("BINARY").value == "/tmp/vuln"

    def test_unknown_pointing_at_absent_step_rejected(self):
        bad = Fact(
            name="OFFSET",
            confidence=Confidence.UNKNOWN,
            unknown_reason="probe failed.",
            plausible="72 or 88",
            resolved_by="a_step_that_does_not_exist",
        )
        with pytest.raises(WalkthroughError, match="not in this walkthrough"):
            make_walkthrough(steps=(make_step("offset", produces=(bad,)),))

    def test_unknowns_collects_across_constants_and_steps(self):
        unknown = Fact(
            name="CANARY",
            confidence=Confidence.UNKNOWN,
            unknown_reason="no read primitive was found to disclose it.",
            plausible="8 bytes whose least-significant byte is 0x00",
            resolved_by="chain",
        )
        wt = make_walkthrough(
            constants=(make_fact(name="BINARY", value="/tmp/vuln", kind="str"),),
            steps=(
                make_step("offset", produces=(make_fact(), unknown)),
                make_step("chain", consumes=("OFFSET",)),
            ),
        )
        assert [f.name for f in wt.unknowns] == ["CANARY"]
        assert len(wt.all_facts()) == 3

    def test_fact_cannot_be_resolved_by_the_step_that_produces_it(self):
        circular = Fact(
            name="CANARY",
            confidence=Confidence.UNKNOWN,
            unknown_reason="not disclosed.",
            plausible="8 bytes ending in 0x00",
            resolved_by="offset",
        )
        with pytest.raises(WalkthroughError, match="also claims to be resolved by it"):
            make_walkthrough(steps=(make_step("offset", produces=(circular,)),))


class TestRuntimeFacts:
    """A leaked address is only valid inside the process that leaked it.

    Baking a generation-time leak into a constant would produce a script that
    works exactly once, on the generating host -- a worse artifact than the
    `TODO` this package replaces, because it lies with a `# measured` comment
    attached. So the model refuses it.
    """

    def make_runtime_fact(self):
        return Fact(
            name="LIBC_BASE",
            kind="addr",
            runtime=True,
            confidence=Confidence.DERIVED,
            evidence=Evidence(
                method="leaked at runtime, then libc_base = leak - libc.sym.puts",
                command="puts(puts@got) via a ROP chain",
            ),
            description="ASLR'd libc load address; different every run.",
        )

    def test_runtime_fact_needs_no_static_value(self):
        fact = self.make_runtime_fact()
        assert fact.value is None
        assert fact.is_known

    def test_runtime_fact_refuses_to_render_as_a_constant(self):
        with pytest.raises(WalkthroughError, match="only valid inside the process"):
            self.make_runtime_fact().render_assignment()

    def test_runtime_fact_rejected_in_the_constants_block(self):
        with pytest.raises(WalkthroughError, match="cannot be a module constant"):
            make_walkthrough(constants=(self.make_runtime_fact(),))

    def test_runtime_fact_is_fine_as_a_step_output(self):
        runtime = self.make_runtime_fact()
        wt = make_walkthrough(
            steps=(
                make_step("leak", produces=(runtime,)),
                make_step("chain", consumes=("LIBC_BASE",)),
            )
        )
        assert wt.fact("LIBC_BASE").runtime is True
        assert wt.to_dict()["steps"][0]["produces"][0]["runtime"] is True


class TestNameSafety:
    def test_python_keyword_rejected(self):
        with pytest.raises(WalkthroughError, match="keyword"):
            make_fact(name="class")

    @pytest.mark.parametrize("name", ["context", "flat", "p64", "process", "elf"])
    def test_pwntools_shadowing_names_rejected(self, name):
        # The generated script does `from pwn import *`; shadowing one of these
        # breaks it in a way no reader would diagnose.
        assert name in RESERVED_FACT_NAMES
        with pytest.raises(WalkthroughError, match="shadow"):
            make_fact(name=name)

    def test_hyphenated_step_id_rejected(self):
        # `function_name` would emit `def step_find-offset():` -- a SyntaxError.
        with pytest.raises(WalkthroughError, match="valid Python identifier"):
            make_step("find-offset")

    def test_kind_and_value_must_agree(self):
        with pytest.raises(WalkthroughError, match="kind 'addr'"):
            make_fact(name="POP_RDI", value="0x4011fa", kind="addr")
        with pytest.raises(WalkthroughError, match="kind 'bytes'"):
            make_fact(name="BINSH", value="/bin/sh", kind="bytes")


class TestEvidenceIsMandatory:
    def test_measured_without_evidence_rejected(self):
        with pytest.raises(WalkthroughError, match="carries no Evidence"):
            Fact(name="OFFSET", value=72, confidence=Confidence.MEASURED)

    def test_measured_evidence_must_show_its_work(self):
        with pytest.raises(WalkthroughError, match="must record the command"):
            Fact(
                name="OFFSET",
                value=72,
                confidence=Confidence.MEASURED,
                evidence=Evidence(method="analysis"),
            )

    def test_default_confidence_is_not_the_most_trustworthy(self):
        # A family that forgets the keyword must not be handed MEASURED.
        assert Fact(name="LIBC", value="/lib/libc.so.6", kind="str").confidence is (
            Confidence.ASSUMED
        )

    def test_unknown_may_not_carry_a_value(self):
        with pytest.raises(WalkthroughError, match="must not carry a value"):
            Fact(
                name="OFFSET",
                value=72,
                confidence=Confidence.UNKNOWN,
                unknown_reason="probe failed.",
                plausible="72 or 88",
                resolved_by="offset",
            )

    def test_missing_lookups_raise_keyerror(self):
        wt = make_walkthrough()
        for call in (lambda: wt.fact("NOPE"), lambda: wt.step("nope"),
                     lambda: wt.number_of("nope")):
            with pytest.raises(KeyError):
                call()


class TestRouteDecisionTree:
    def test_primary_is_highest_scoring_viable_route(self):
        routes = (
            make_route("ret2plt/system", 0.9),
            make_route("ret2libc via leak", 0.5, rationale="Possible, needs a leak."),
            make_route(
                "stack shellcode",
                0.0,
                applicable=False,
                rationale="NX is enabled, so stack pages are not executable.",
                rejection=Rejection.STRUCTURAL,
            ),
        )
        wt = make_walkthrough(routes=routes)
        assert wt.primary_route.name == "ret2plt/system"
        # The rejected routes ARE the decision tree, viable ones ranked first.
        fallbacks = wt.fallback_routes
        assert [r.name for r in fallbacks] == ["ret2libc via leak", "stack shellcode"]
        # Every rejected route must explain itself.
        assert all(r.rationale for r in fallbacks)

    def test_scores_are_confined_to_a_shared_scale(self):
        # Scores are compared across families, so an enthusiastic author must
        # not be able to outrank a modest one by changing units.
        with pytest.raises(WalkthroughError, match="outside 0.0-1.0"):
            make_route("overeager", 95.0)

    def test_non_applicable_route_must_classify_its_rejection(self):
        with pytest.raises(WalkthroughError, match="structural or transient"):
            Route("ret2libc", 0.0, False, "No libc leak obtained.")

    def test_structural_and_transient_rejections_are_distinguished(self):
        structural = make_route(
            "ret2libc",
            0.0,
            applicable=False,
            rationale="The binary is statically linked; there is no libc.",
            rejection=Rejection.STRUCTURAL,
        )
        transient = make_route(
            "ret2libc",
            0.3,
            applicable=False,
            rationale="The leak step did not produce an address this run.",
            rejection=Rejection.TRANSIENT,
            becomes_viable_if="step 'leak' succeeds and yields a libc address",
        )
        # A reader must be able to tell which fallback is worth trying.
        assert not structural.is_actionable_fallback
        assert transient.is_actionable_fallback
        assert "ruled out (structural)" in structural.describe()
        assert "Becomes viable if" in transient.describe()

    def test_no_viable_route_leaves_primary_none(self):
        wt = make_walkthrough(
            routes=(
                make_route(
                    "stack shellcode", 0.0, applicable=False,
                    rationale="NX is enabled.",
                ),
            )
        )
        assert wt.primary_route is None
        assert len(wt.fallback_routes) == 1

    def test_duplicate_route_names_rejected(self):
        with pytest.raises(WalkthroughError, match="Route names must be unique"):
            make_walkthrough(routes=(make_route(), make_route()))

    def test_routes_are_mandatory(self):
        with pytest.raises(WalkthroughError, match="routes considered"):
            make_walkthrough(routes=())

    def test_route_describe_names_the_unmet_requirement(self):
        route = make_route(
            "SROP",
            0.8,
            requires=(
                Requirement("a syscall gadget", True),
                Requirement("control of rax", False),
            ),
        )
        described = route.describe()
        assert "VIABLE" in described
        # Only the requirement that actually fails is called out.
        assert "Missing: control of rax." in described
        assert "syscall gadget" not in described.split("Missing:")[1]


class TestProtectionReasoning:
    def test_verdict_describes_consequence_not_just_state(self):
        verdict = ProtectionVerdict(
            name="NX",
            state="enabled",
            implication="stack pages are not executable.",
            rules_out=("stack shellcode", "ret2shellcode"),
            forces="reuse existing executable code, i.e. ROP.",
        )
        described = verdict.describe()
        assert "NX: enabled" in described
        assert "Rules out: stack shellcode, ret2shellcode." in described
        assert "Forces:" in described

    def test_verdict_without_consequences_still_describes(self):
        verdict = ProtectionVerdict("Canary", "absent", "nothing detects the overwrite.")
        assert "Rules out" not in verdict.describe()


class TestSerialisation:
    def test_to_dict_exposes_the_full_teaching_content(self):
        unknown = Fact(
            name="CANARY",
            confidence=Confidence.UNKNOWN,
            unknown_reason="no canary read primitive was found.",
            plausible="8 bytes ending in 0x00",
            resolved_by="offset",
        )
        wt = make_walkthrough(
            constants=(make_fact(name="POP_RDI", value=0x4011FA, kind="addr"),),
            protections=(ProtectionVerdict("NX", "enabled", "no exec stack."),),
            steps=(
                make_step("offset", produces=(make_fact(),)),
                make_step(
                    "leak",
                    consumes=("OFFSET",),
                    produces=(unknown,),
                    on_failure=(Fallback("no output", "chain misaligned", "add a ret"),),
                    manual=(ManualCommand("inspect", "gdb ./vuln"),),
                ),
            ),
            routes=(make_route("ret2libc", 0.9, rationale="needs a leak."),),
            automation_failure="autopwn failed at DELIVERY on ret2libc.",
            provenance=("phase-4 handoff", "pwntools ROP"),
        )
        data = wt.to_dict()

        assert data["family"] == "rop_chain"
        assert data["automation_failure"].startswith("autopwn failed")
        assert data["provenance"] == ["phase-4 handoff", "pwntools ROP"]
        assert data["constants"][0]["rendered"] == "0x4011fa"
        assert data["constants"][0]["value"] == 0x4011FA
        # The assembled exploit and the chosen route must be machine-readable.
        assert data["final_exploit"] == "p = process(BINARY); p.send(payload)"
        assert data["primary_route"] == "ret2libc"
        assert data["protections"][0]["name"] == "NX"
        assert [s["number"] for s in data["steps"]] == [1, 2]
        assert data["steps"][1]["consumes"] == ["OFFSET"]
        assert data["steps"][1]["on_failure"][0]["symptom"] == "no output"
        assert data["steps"][1]["manual"][0]["command"] == "gdb ./vuln"
        assert data["routes"][0]["applicable"] is True
        # Unknowns are surfaced at the top level so a consumer can show
        # "here is exactly what is still missing".
        assert [u["name"] for u in data["unknowns"]] == ["CANARY"]
        assert data["unknowns"][0]["rendered"] is None
        assert data["unknowns"][0]["resolved_by"] == "offset"

    def test_to_dict_is_json_serialisable(self):
        import json

        json.dumps(make_walkthrough().to_dict())


class TestHelpers:
    def test_dedent_code_normalises_indented_literals(self):
        assert dedent_code(
            """
            p = process(BINARY)
            p.send(payload)
            """
        ) == "p = process(BINARY)\np.send(payload)"

    def test_comment_block_prefixes_every_line(self):
        # Multi-line prose (a gdb script, an evidence detail) must not leak
        # bare text into the generated source.
        rendered = comment_block("first line\nsecond line")
        assert rendered == "# first line\n# second line"

    def test_multiline_description_still_yields_valid_source(self):
        fact = make_fact(description="line one\nline two")
        for line in fact.render_assignment().splitlines():
            assert line.startswith("#") or "=" in line

    def test_unknown_detail_reads_cleanly_without_double_punctuation(self):
        fact = Fact(
            name="OFFSET",
            confidence=Confidence.UNKNOWN,
            unknown_reason="the probe produced no fault",  # no trailing period
            plausible="72 or 88",
            resolved_by="offset",
        )
        assert "no fault. Plausible: 72 or 88." in fact.unknown_detail


class TestGadgetConstantReferences:
    """Step code may not name a ``G_*`` constant the walkthrough never declares.

    Regression guard for a bug that produced a syntactically perfect file which
    raised ``NameError: name 'G_RET' is not defined`` on the reader's first
    command: a shared step builder emitted checks for every gadget found in the
    binary, while each family declared constants only for the gadgets its own
    route used.
    """

    def test_step_referencing_an_undeclared_gadget_is_rejected(self):
        with pytest.raises(WalkthroughError, match="G_RET"):
            make_walkthrough(
                steps=(make_step(code="log.info('%#x', G_RET)"),),
            )

    def test_final_exploit_referencing_an_undeclared_gadget_is_rejected(self):
        with pytest.raises(WalkthroughError, match="G_POP_RDI"):
            make_walkthrough(final_exploit="rop = [G_POP_RDI, 0x1234]")

    def test_declared_gadget_constant_is_accepted(self):
        wt = make_walkthrough(
            constants=(make_fact(name="G_RET", value=0x40101A),),
            steps=(make_step(code="log.info('%#x', G_RET)"),),
        )
        assert wt.steps[0].code

    def test_a_gadget_produced_by_an_earlier_step_also_counts(self):
        produced = make_fact(name="G_POP_RDI", value=0x4011FA)
        wt = make_walkthrough(
            steps=(
                make_step(step_id="find", produces=(produced,)),
                make_step(step_id="use", code="rop = [G_POP_RDI]"),
            ),
        )
        assert len(wt.steps) == 2
