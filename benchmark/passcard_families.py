"""Two-axis family taxonomy for the passcard (SP-01 plan section 2.2).

The tool names an exploit three ways: the 15 ``ExploitApproach`` members that
``pwn`` recommends, the ``template -t`` choices, and the technique ids that
``build_default_registry()`` registers. This module maps every name in those
three vocabularies to exactly one ``(axis, family)`` pair, or to ``unscored``
with a reason.

* ``method`` axis: HOW the target is exploited. This is what METHOD-R0,
  METHOD-L and TEMPLATE compare against a target's ``method_accept``.
* ``vuln`` axis: WHAT defect is abused. A vuln-axis recommendation can never
  satisfy a method accept-set; it is reported in the informational VULN column.
* ``unscored``: names that are neither (a modifier, a stage, a selector).

``tests/test_passcard_families.py`` enumerates the three vocabularies at runtime,
so a name added to the product without an entry here fails that test.

Policy for the registry ids: an executor named for the payoff it delivers is a
method; an executor named for the defect it abuses is on the vuln axis.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

METHOD_FAMILIES: Tuple[str, ...] = (
    "ret2win",
    "ret2libc",
    "rop_syscall",
    "srop",
    "ret2dlresolve",
    "shellcode",
    "stack_pivot",
    "one_gadget",
    "fmt_write",
    "got_overwrite",
    "objptr_hijack",
    "heap_metadata",
    "fsop",
    "data_only",
    "env_hijack",
)

VULN_FAMILIES: Tuple[str, ...] = (
    "stack_bof",
    "heap_overflow",
    "uaf",
    "double_free",
    "integer",
    "format_string",
    "off_by_one",
    "logic",
)

METHOD = "method"
VULN = "vuln"
UNSCORED = "unscored"

# A mapping value is (axis, family) or (UNSCORED, reason).
Mapping = Tuple[str, str]


def _m(family: str) -> Mapping:
    assert family in METHOD_FAMILIES, family
    return (METHOD, family)


def _v(family: str) -> Mapping:
    assert family in VULN_FAMILIES, family
    return (VULN, family)


def _u(reason: str) -> Mapping:
    return (UNSCORED, reason)


# ``ExploitApproach`` member names, as ``pwn --json`` emits them.
APPROACH_MAP: Dict[str, Mapping] = {
    "RET2WIN": _m("ret2win"),
    "ROP_EXECVE": _m("rop_syscall"),
    "ROP_SYSTEM": _m("ret2libc"),
    "SROP": _m("srop"),
    "MPROTECT_SHELLCODE": _m("shellcode"),
    "STACK_PIVOT": _m("stack_pivot"),
    "FORMAT_STRING": _m("fmt_write"),
    # system() through the binary's own PLT is ret2libc without the leak.
    "RET2PLT": _m("ret2libc"),
    "RET2DLRESOLVE": _m("ret2dlresolve"),
    "ONE_GADGET": _m("one_gadget"),
    "SHELLCODE": _m("shellcode"),
    # The suggester's heap steps are tcache/fastbin/House-of metadata attacks.
    "HEAP_EXPLOIT": _m("heap_metadata"),
    "SECCOMP_BYPASS": _u("a filter to get past, not an exploitation method"),
    # Overwrite an adjacent stack variable: no control flow is hijacked.
    "VARIABLE_OVERWRITE": _m("data_only"),
    # The defect (signed size check), not the payoff, names this approach.
    "NEGATIVE_SIZE_BYPASS": _v("integer"),
}

# ``template -t`` choices, as ``template --json`` echoes them in ``technique``.
TEMPLATE_MAP: Dict[str, Mapping] = {
    "ret2win": _m("ret2win"),
    "shellcode": _m("shellcode"),
    "ret2system": _m("ret2libc"),
    "ret2libc": _m("ret2libc"),
    "srop": _m("srop"),
    "leak": _u("a leak stage only; it completes no exploit"),
    "auto": _u("delegates to the selector and names no method"),
}

# ``build_default_registry()`` technique ids.
TECHNIQUE_MAP: Dict[str, Mapping] = {
    "env_path_hijack": _m("env_hijack"),
    "heap_strlen_ofb1": _m("heap_metadata"),
    "objptr_hijack": _m("objptr_hijack"),
    # TOCTOU, symlink and traversal pick which file is touched; no code runs.
    "toctou_path_race": _m("data_only"),
    "symlink_follow_write": _m("data_only"),
    "path_traversal_read": _m("data_only"),
    "uninit_disclosure": _m("data_only"),
    # The loader's search path is part of the process environment.
    "library_path_hijack": _m("env_hijack"),
    # Command injection reaches a shell with no memory corruption.
    "subprocess_injection": _m("data_only"),
    "weak_prng_replay": _m("data_only"),
    # Leaks the canary and PIE base, then returns into the win function.
    "scanf_scalar_overwrite": _m("ret2win"),
    # The proven S0 technique for ancient_interface: a ROP chain into libc.
    "eintr_accumulator_rop": _m("ret2libc"),
    "srop_symtab_pivot": _m("srop"),
    "variable_overwrite": _m("data_only"),
    "ret2win": _m("ret2win"),
    "ret2plt": _m("ret2libc"),
    # Defect-named executors: each ends in a win call, but the defect names it.
    "int_truncation_bypass": _v("integer"),
    "negative_index_write": _v("integer"),
    "canary_leak_ret2win": _m("ret2win"),
    "fmtstr_write_gate": _m("fmt_write"),
    "direct_shellcode": _m("shellcode"),
    "stack_shellcode": _m("shellcode"),
    "ret2libc_leak": _m("ret2libc"),
    "ret2dlresolve": _m("ret2dlresolve"),
    "srop": _m("srop"),
    # Tcache poisoning corrupts allocator metadata, whatever it aims the write at.
    "tcache_poison_got": _m("heap_metadata"),
    "heap_record_hijack": _m("objptr_hijack"),
    "scanf_canary_bypass": _m("ret2win"),
    "uaf": _v("uaf"),
    "double_free": _v("double_free"),
    "container_file_rop": _m("rop_syscall"),
    "alloc_size_overflow": _v("integer"),
    # A writable table of code pointers, the same class as a GOT entry.
    "fini_array_write": _m("got_overwrite"),
    "off_by_one_guard": _v("off_by_one"),
    "heap_uaf_read": _v("uaf"),
    # No overflow and no bad index: a tag-guarded call, so a logic defect.
    "type_confusion_tag": _v("logic"),
    "loop_counter_overflow": _v("integer"),
    "heap_offbynul_overlap": _m("heap_metadata"),
    "oob_index_read_exfil": _m("data_only"),
    "fsop_stdout_read": _m("fsop"),
}


def _merge(*maps: Dict[str, Mapping]) -> Dict[str, Mapping]:
    """Merge the vocabularies under lowercase keys.

    The same name may appear in more than one vocabulary (``srop`` is an
    approach, a template choice and a technique id); the mappings must agree.
    """
    merged: Dict[str, Mapping] = {}
    for vocabulary in maps:
        for name, mapping in vocabulary.items():
            key = name.lower()
            if merged.setdefault(key, mapping) != mapping:
                raise ValueError(f"conflicting mappings for {name!r}")
    return merged


NAME_MAP: Dict[str, Mapping] = _merge(APPROACH_MAP, TEMPLATE_MAP, TECHNIQUE_MAP)


def map_name(name: object) -> Optional[Mapping]:
    """Map a tool name to ``(axis, family)``, ``("unscored", reason)`` or ``None``.

    Matching ignores case and surrounding whitespace. A bare method-family name
    (``fsop``, ``one_gadget``) maps to itself, so a recommender may name a family
    directly. ``None`` means the name is not in the vocabulary; the scorer treats
    that as a FAIL with a warning.
    """
    if not isinstance(name, str):
        return None
    key = name.strip().lower()
    if key in NAME_MAP:
        return NAME_MAP[key]
    if key in METHOD_FAMILIES:
        return (METHOD, key)
    return None
