"""Seeded C synthesis for the W-2 falsifier corpus (design §3a).

25 adversarial control-flow shapes, plus a strip twin and a PE variant of
``gate_disj`` (27 units total), each a standalone non-PIE unstripped ELF (or, for
the two ``gate_disj`` variants, a stripped ELF / a PE) with exactly one
``__attribute__((noinline, used))`` candidate function and a real ``system()``
sink, so W-1 still promotes it and the W-2 required-args pass actually runs on
it. ``main`` never calls the candidate. Every identifier is drawn from
``payoff_names.Namespace.fresh()`` (never a literal like ``"gate_audit"`` in the
generated C), so the namespace-disjointness check applies here exactly as it
does to the main corpus.

Truth is not a randomized fact for these units: each shape's
``(args_status, required_args, args_reason)`` triple is exactly what the §3a
table specifies; only the drawn constants vary by seed. Two extra bespoke
fixtures also live here (not part of the 27, no ``role: "falsifier"``):

* the mixed float/int ABI positive (§6 T13) -- ``win(double unused, long
  key)`` -- proving a leading XMM-class parameter does not shift the integer
  parameter's register/slot;
* the overflowable ret2win e2e fixtures (§6 T12, built by ``payoff_fixtures``
  alongside this module) are intentionally kept separate since they need a
  real, deterministic stack layout rather than a bespoke control-flow shape.
"""

from __future__ import annotations

import dataclasses
import random
from typing import Dict, List, Optional, Tuple

from payoff_names import Namespace
from payoff_source import KEEP, SYSTEM_COMMANDS, _Consts, _exec_lines, _function, _indent

FALSIFIER_SHAPES: Tuple[str, ...] = (
    "decoy_sink",
    "gate_audit",
    "gate_relaudit",
    "gate_invert",
    "gate_disj",
    "gate_disjineq",
    "gate_relational",
    "gate_arith",
    "gate_mixed",
    "gate_bool",
    "gate_boolnongate",
    "gate_boolor",
    "gate_reload",
    "gate_nonconst",
    "gate_paramcmp",
    "gate_multieq",
    "gate_abistack",
    "gate_loop",
    "gate_negeq",
    "gate_neginv",
    "gate_nonconst_copy",
    "gate_u8_pair",
    "gate_u8_full",
    "gate_u16_sparse",
    "gate_u64_sparse",
)

# Reasons the extractor may give for an "unknown" result (design §2.3 reason
# precedence). None of the falsifier shapes below hit irreducible_cflow,
# analysis_exception or conflict -- those are proved elsewhere.
REASONS = (
    "bool_compose",
    "bool_fanout",
    "ambiguous_gate",
    "nonconst_gate",
    "avoidance_gate",
    "relational_gate",
    "unresolved_gate",
    "abi_class",
)


@dataclasses.dataclass
class FalsifierProgram:
    source: str
    function_name: str  # the one candidate function's generated C name
    globals_: List[str]  # generated global identifiers (may be empty)
    shape: str  # falsifier shape key, e.g. "gate_audit" -- bookkeeping only
    args_status: str  # "known" | "unknown"
    required_args: List[Dict[str, int]]
    args_reason: Optional[str]
    detail: Dict[str, object]

    @property
    def names(self) -> List[str]:
        return sorted([self.function_name] + self.globals_)


def _benign_stmt(ns: Namespace) -> List[str]:
    """A non-empty, side-effect-free statement for a branch arm that must not
    be sink-reaching but also must not vanish at -O0 (it never does -- -O0
    never deletes a dead store -- this is just for readability of the
    generated source)."""
    local = ns.fresh()
    return ["int %s = 1;" % local, "(void)%s;" % local]


def _sink(rng: random.Random) -> List[str]:
    return _exec_lines("system", rng.choice(SYSTEM_COMMANDS))


def _small_distinct(rng: random.Random, lo: int, hi: int, count: int) -> List[int]:
    """``count`` distinct ints in [lo, hi), via rejection so the stream shape
    matches ``_Consts.draw`` without needing the 31-bit range."""
    seen: set = set()
    out: List[int] = []
    while len(out) < count:
        v = rng.randrange(lo, hi)
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


# ---------------------------------------------------------------------------
# One builder per shape. Each returns (function_text_lines are already baked
# into the Function by _function; here we just return the pieces the caller
# assembles): (Function, globals_text, globals_names, args_status,
# required_args, args_reason, extra_detail).


def _build_decoy_sink(rng, ns, consts) -> dict:
    name = ns.fresh()
    g_name = ns.fresh()
    c1, c2 = consts.drawn(), consts.drawn()
    # The compares must SURVIVE decompilation for this to be a control at all:
    # constant-valued locals (the original r = 16; v = r * 3 + 11) are folded
    # away by the decompiler, leaving no INT_EQUAL in the high P-code, so the
    # "non-parameter constants are rejected" check would be vacuous. A
    # call-return (not a param, not a memory global) compared against constants,
    # with live branch bodies (a store to a global) so the compares are not
    # dead-code eliminated, keeps real non-param equalities in the P-code.
    body = [
        "long r = (long)getpid();",
        "if (r == %s) {" % c1,
        "    %s = 1;" % g_name,
        "}",
        "if (r == %s) {" % c2,
        "    %s = 2;" % g_name,
        "}",
        *_sink(rng),
    ]
    func = _function("payoff", "void", name, "void", body)
    gdef = "long %s;" % g_name
    return dict(func=func, globals_text=[gdef], globals_names=[g_name], status="known",
                required=[], reason=None)


def _build_gate_audit(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    params = "int a"
    body = ["if (a == %s) {" % x, *_indent(_benign_stmt(ns)), "}", *_sink(rng)]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="known",
                required=[], reason=None)


def _build_gate_relaudit(rng, ns, consts) -> dict:
    name = ns.fresh()
    k = consts.drawn()
    params = "int a"
    body = ["if (a > %s) {" % k, *_indent(_benign_stmt(ns)), "}", *_sink(rng)]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="known",
                required=[], reason=None)


def _build_gate_invert(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    params = "int a"
    body = ["if (a == %s) {" % x, "    return;", "}", *_sink(rng)]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="avoidance_gate")


def _build_gate_disj(rng, ns, consts) -> dict:
    name = ns.fresh()
    x, y = consts.drawn(), consts.drawn()
    params = "int a"
    body = ["if (a == %s || a == %s) {" % (x, y), *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="unresolved_gate")


def _build_gate_disjineq(rng, ns, consts) -> dict:
    name = ns.fresh()
    x, z = consts.drawn(), consts.drawn()
    params = "int a"
    body = ["if (a == %s || a != %s) {" % (x, z), *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="unresolved_gate")


def _build_gate_relational(rng, ns, consts) -> dict:
    name = ns.fresh()
    k = consts.drawn()
    params = "int a"
    body = ["if (a > %s) {" % k, *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="relational_gate")


def _build_gate_arith(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    params = "int a"
    body = [
        "long b = (long)a * 2L;",
        "if (b == %s) {" % x,
        *_indent(_sink(rng)),
        "}",
    ]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="ambiguous_gate")


def _build_gate_mixed(rng, ns, consts) -> dict:
    name = ns.fresh()
    x, y, z = consts.drawn(), consts.drawn(), consts.drawn()
    params = "int a, int b"
    body = [
        "if (a == %s && (b == %s || b == %s)) {" % (x, y, z),
        *_indent(_sink(rng)),
        "}",
    ]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="unresolved_gate")


def _build_gate_bool(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    c_name = ns.fresh()
    f_name = ns.fresh()
    params = "int a, int %s" % f_name
    body = [
        "int %s = (a == %s);" % (c_name, x),
        "if (%s & %s) {" % (c_name, f_name),
        *_indent(_sink(rng)),
        "} else {",
        "    return;",
        "}",
    ]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="bool_compose")


def _build_gate_boolnongate(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    c_name = ns.fresh()
    f_name = ns.fresh()
    params = "int a, int %s" % f_name
    body = [
        "int %s = (a == %s) & %s;" % (c_name, x, f_name),
        "if (%s) {" % c_name,
        *_indent(_benign_stmt(ns)),
        "}",
        *_sink(rng),
    ]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="known",
                required=[], reason=None)


def _build_gate_boolor(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    flag_g = ns.fresh()
    params = "int a"
    body = ["if (a == %s || %s) {" % (x, flag_g), *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    gdef = "int %s;" % flag_g
    return dict(func=func, globals_text=[gdef], globals_names=[flag_g],
                status="unknown", required=[], reason="unresolved_gate")


def _build_gate_reload(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    g_name = ns.fresh()
    params = "long a"
    # A plain local round-trip is forwarded by the decompiler straight back
    # to param_1 (no memory-backed def), which would wrongly resolve to a
    # pinnable PARAM(full). Routing the value through a genuine global and
    # across an intervening external call forces Ghidra to mark the reload
    # as an INDIRECT-defined varnode, which the slot lattice maps to
    # AMBIGUOUS -- exactly the "can't tell a reloaded param from a global"
    # case this falsifier is meant to exercise.
    body = [
        "%s = a;" % g_name,
        "(void)getpid();",
        "if (%s == %s) {" % (g_name, x),
        *_indent(_sink(rng)),
        "}",
    ]
    gdef = "long %s;" % g_name
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[gdef], globals_names=[g_name], status="unknown",
                required=[], reason="ambiguous_gate")


def _build_gate_nonconst(rng, ns, consts) -> dict:
    name = ns.fresh()
    g_name = ns.fresh()
    g_val = consts.drawn()
    params = "long a"
    body = ["if (a == %s) {" % g_name, *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    gdef = "long %s = %sL;" % (g_name, g_val)
    return dict(func=func, globals_text=[gdef], globals_names=[g_name],
                status="unknown", required=[], reason="nonconst_gate")


def _build_gate_paramcmp(rng, ns, consts) -> dict:
    name = ns.fresh()
    params = "long a, long b"
    body = ["if (a == b) {", *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="nonconst_gate")


def _build_gate_multieq(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    sel_g = ns.fresh()
    v_name = ns.fresh()
    params = "long a, long b"
    body = [
        "long %s;" % v_name,
        "if (%s) {" % sel_g,
        "    %s = a;" % v_name,
        "} else {",
        "    %s = b;" % v_name,
        "}",
        "if (%s == %s) {" % (v_name, x),
        *_indent(_sink(rng)),
        "}",
    ]
    func = _function("payoff", "void", name, params, body)
    gdef = "int %s;" % sel_g
    return dict(func=func, globals_text=[gdef], globals_names=[sel_g],
                status="unknown", required=[], reason="ambiguous_gate")


def _build_gate_abistack(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    sink_g = ns.fresh()
    # `(void)aN;` on an otherwise-unused formal compiles to nothing (no P-code
    # at all), so Ghidra never sees a read of RDI/RSI/RDX/RCX/R8/R9 and
    # therefore never infers a register-ABI signature for this (uncalled, so
    # no call-site to infer from either) function -- a1..a6 end up with
    # *zero* HighParams, and a7's read of [rsp+8] decompiles as a bare
    # unrecognized `HighLocal` (isParam=false), not a stack-passed HighParam,
    # so it never reaches the PARAM(full) path at all and the falsifier can't
    # exercise `abi_class`. Routing a1..a6 through a genuine arithmetic use
    # (stored to a global so -O0 keeps it) forces Ghidra to see all six
    # integer-register reads, so it correctly infers the full 7-arg ABI shape
    # and promotes a7's stack read to the 7th formal (R8).
    params = ", ".join("long a%d" % i for i in range(1, 8))
    body = [
        "%s = a1 + a2 + a3 + a4 + a5 + a6;" % sink_g,
        "if (a7 == %s) {" % x,
        *_indent(_sink(rng)),
        "}",
    ]
    func = _function("payoff", "void", name, params, body)
    gdef = "long %s;" % sink_g
    return dict(func=func, globals_text=[gdef], globals_names=[sink_g],
                status="unknown", required=[], reason="abi_class")


def _build_gate_loop(rng, ns, consts) -> dict:
    name = ns.fresh()
    # The design's worked case is `if (nondet()) for(;;){} sink;` -- an
    # UNCONTROLLED branch (no parameter anywhere) that must stay a non-gate
    # compare so it bypasses Step 1 entirely and is left adversarial for
    # Step 2's must-reach fixed point (the real point of this falsifier:
    # proving `Entry notin MustReachSink` on a cyclic CFG, R9/R11). A bare
    # global fails that: Ghidra 12.1.3 represents an unwritten global read as
    # a bare RAM-address input varnode with no LOAD op (the design's MEM
    # substitute for LOAD, §2.1), so `global != 0` classifies MEM-vs-const ==
    # ambiguous-param, and since this is the *only* branch in the function it
    # individually gates -> Step 1 taints it `ambiguous_gate` before Step 2
    # ever runs, which is correct per §2.1's own MEM rule but not what this
    # falsifier is meant to exercise. A niladic external call's return value
    # traces through CALL's own inputs to NONPARAM (the call target is a bare
    # "ram"-space reference with no HighVariable, so it is NONPARAM too, not
    # MEM -- a hardcoded code address is not a memory-resident *value*), so
    # `rand() != 0` is NONPARAM vs NONPARAM == non-gate == truly uncontrolled,
    # matching `nondet()`.
    body = [
        "if (rand() != 0) {",
        "    for (;;) {",
        "    }",
        "}",
        *_sink(rng),
    ]
    func = _function("payoff", "void", name, "void", body)
    return dict(func=func, globals_text=[], globals_names=[],
                status="unknown", required=[], reason="unresolved_gate")


def _build_gate_negeq(rng, ns, consts) -> dict:
    name = ns.fresh()
    x_val = consts.draw()
    x = consts.spell(x_val)
    params = "int a"
    body = [
        "if (!(a != %s)) {" % x,
        *_indent(_sink(rng)),
        "} else {",
        *_indent(_benign_stmt(ns)),
        "}",
    ]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="known",
                required=[{"position": 1, "value": x_val}], reason=None)


def _build_gate_neginv(rng, ns, consts) -> dict:
    name = ns.fresh()
    x = consts.drawn()
    params = "int a"
    body = [
        "if (!(a == %s)) {" % x,
        *_indent(_sink(rng)),
        "} else {",
        *_indent(_benign_stmt(ns)),
        "}",
    ]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="avoidance_gate")


def _build_gate_nonconst_copy(rng, ns, consts) -> dict:
    name = ns.fresh()
    g_name = ns.fresh()
    g_val = consts.drawn()
    tmp_name = ns.fresh()
    params = "long a"
    body = [
        "long %s = %s;" % (tmp_name, g_name),
        "if (a == %s) {" % tmp_name,
        *_indent(_sink(rng)),
        "}",
    ]
    func = _function("payoff", "void", name, params, body)
    gdef = "long %s = %sL;" % (g_name, g_val)
    return dict(func=func, globals_text=[gdef], globals_names=[g_name],
                status="unknown", required=[], reason="nonconst_gate")


def _build_gate_u8_pair(rng, ns, consts) -> dict:
    name = ns.fresh()
    params = "unsigned char a"
    body = ["if (a == 0 || a == 1) {", *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="unresolved_gate")


def _build_gate_u8_full(rng, ns, consts) -> dict:
    name = ns.fresh()
    params = "unsigned char a"
    arms = " || ".join("a == %d" % v for v in range(256))
    body = ["if (%s) {" % arms, *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="known",
                required=[], reason=None)


def _build_gate_u16_sparse(rng, ns, consts) -> dict:
    name = ns.fresh()
    a, b, c = _small_distinct(rng, 0, 1 << 16, 3)
    params = "unsigned short a"
    body = ["if (a == %d || a == %d || a == %d) {" % (a, b, c),
            *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="unresolved_gate")


def _build_gate_u64_sparse(rng, ns, consts) -> dict:
    name = ns.fresh()
    a, b = consts.draw(), consts.draw()
    params = "unsigned long a"
    body = ["if (a == %dUL || a == %dUL) {" % (a, b), *_indent(_sink(rng)), "}"]
    func = _function("payoff", "void", name, params, body)
    return dict(func=func, globals_text=[], globals_names=[], status="unknown",
                required=[], reason="unresolved_gate")


_BUILDERS = {
    "decoy_sink": _build_decoy_sink,
    "gate_audit": _build_gate_audit,
    "gate_relaudit": _build_gate_relaudit,
    "gate_invert": _build_gate_invert,
    "gate_disj": _build_gate_disj,
    "gate_disjineq": _build_gate_disjineq,
    "gate_relational": _build_gate_relational,
    "gate_arith": _build_gate_arith,
    "gate_mixed": _build_gate_mixed,
    "gate_bool": _build_gate_bool,
    "gate_boolnongate": _build_gate_boolnongate,
    "gate_boolor": _build_gate_boolor,
    "gate_reload": _build_gate_reload,
    "gate_nonconst": _build_gate_nonconst,
    "gate_paramcmp": _build_gate_paramcmp,
    "gate_multieq": _build_gate_multieq,
    "gate_abistack": _build_gate_abistack,
    "gate_loop": _build_gate_loop,
    "gate_negeq": _build_gate_negeq,
    "gate_neginv": _build_gate_neginv,
    "gate_nonconst_copy": _build_gate_nonconst_copy,
    "gate_u8_pair": _build_gate_u8_pair,
    "gate_u8_full": _build_gate_u8_full,
    "gate_u16_sparse": _build_gate_u16_sparse,
    "gate_u64_sparse": _build_gate_u64_sparse,
}


def synthesize_falsifier(
    rng: random.Random, ns: Namespace, shape: str
) -> FalsifierProgram:
    if shape not in _BUILDERS:
        raise ValueError("unknown falsifier shape %r" % (shape,))
    consts = _Consts(rng)
    built = _BUILDERS[shape](rng, ns, consts)
    func = built["func"]
    required = built["required"]
    # main is handwritten (no KEEP/prototype wanted -- it is the entry point,
    # never called by anything else, and nothing else must call it either).
    main_text = "int main(void)\n{\n    return 0;\n}"
    parts = [
        *built["globals_text"],
        "",
        func.proto,
        "",
        func.text,
        "",
        main_text,
    ]
    header = (
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <fcntl.h>\n"
        "#include <unistd.h>\n"
    )
    source = header + "\n" + "\n".join(parts) + "\n"
    return FalsifierProgram(
        source=source,
        function_name=func.name,
        globals_=sorted(built["globals_names"]),
        shape=shape,
        args_status=built["status"],
        required_args=required,
        args_reason=built["reason"],
        detail={"generated_for": "w2_falsifier"},
    )
