"""Bespoke fixtures for the W-2 ret2win consumer rewire and ABI tests
(design §6 T12, T13).

Unlike the blind-identification corpus (``payoff_source.py``) and the
falsifier corpus (``payoff_falsifiers.py``), these three binaries are not
trying to hide a payoff's identity from the ranker -- T12 exercises the
*delivery* path (``Ret2WinExecutor`` building a real ROP chain from
discovered required args), and T13 exercises ABI register derivation. Using
the literal name ``win`` is correct here (it matches the existing
``WIN_FUNCTIONS`` fast-path and is exactly how the rest of the exploit
framework's own fixtures are named), so these do not go through
``payoff_names``'s namespace-disjointness lint.

T12 (``fix-e2e-arg1`` / ``fix-e2e-arg3``): a non-PIE, no-canary, unstripped
ELF with a single fixed-size stack buffer in ``main`` and a dead
``gadget_stub`` function whose body is pure inline asm, guaranteeing
``pop rdi/rsi/rdx; ret`` and a bare ``ret`` exist in .text regardless of
whatever a generic ROPgadget/ropper scan of this tiny binary's own linked
libc would or would not turn up. The 88-byte offset from the start of
``buf`` to the saved return address, and the need for one extra alignment
``ret`` before the final jump into ``win`` (SysV requires the stack to be
16-byte aligned across the ``call`` inside ``win``'s ``system()``), were
both confirmed empirically (local ``pwntools`` run, not guessed) during
generation of this module -- see the W-2 step-1 commit message.

T13 (``fix-abimix``): ``win(double unused, long key)``. SysV classifies
floating and integer arguments into independent register sequences, so
``unused`` (double) arrives in ``xmm0`` and ``key`` (long) arrives in
``rdi`` -- the *first* integer register -- despite being the second
parameter in the C signature. Confirmed empirically via objdump.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List, Optional

KEEP = "__attribute__((noinline, used))"

_GADGET_ASM = (
    "pop %rdi\n"
    "ret\n"
    "pop %rsi\n"
    "ret\n"
    "pop %rdx\n"
    "ret\n"
    "ret\n"
)

_HEADER = (
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "#include <unistd.h>\n"
)

# buf[64] at rbp-0x50 (confirmed via objdump of the compiled main()), so the
# gap from buf's first byte to the saved-rbp slot is 0x50 (80) bytes, plus
# the 8-byte saved rbp itself = 88 bytes to the first byte of the saved
# return address.
E2E_BUFFER_SIZE = 64
E2E_READ_SIZE = 512
E2E_RET_OFFSET = 88

_MAIN_E2E = (
    "int main(void)\n"
    "{\n"
    "    char buf[%d];\n"
    "    ssize_t n = read(0, buf, %d);\n"
    "    (void)n;\n"
    "    return 0;\n"
    "}\n"
) % (E2E_BUFFER_SIZE, E2E_READ_SIZE)

_GADGET_STUB = (
    "%s\n"
    "void gadget_stub(void)\n"
    "{\n"
    '    __asm__ volatile (\n'
    '        "%s"\n'
    "    );\n"
    "}\n"
) % (KEEP, _GADGET_ASM.replace("\n", '\\n"\n        "'))


@dataclasses.dataclass
class FixtureProgram:
    source: str
    win_name: str
    gadget_stub_name: Optional[str]
    required_args: List[Dict[str, int]]  # [{position, value}]
    required_regs: List[str]  # base register name per required arg, same order
    ret_offset: Optional[int]  # None for the ABI-mix fixture (no overflow)
    detail: Dict[str, object]


def _win_arg1_source() -> str:
    win = (
        "%s\n"
        "void win(long key)\n"
        "{\n"
        "    if (key == 0x1337) {\n"
        '        system("/bin/sh");\n'
        "    }\n"
        "}\n"
    ) % KEEP
    return "\n".join([_HEADER, win, _GADGET_STUB, _MAIN_E2E])


def _win_arg3_source() -> str:
    win = (
        "%s\n"
        "void win(long a, long b, long c)\n"
        "{\n"
        "    if (a == 0x1111 && b == 0x2222 && c == 0x3333) {\n"
        '        system("/bin/sh");\n'
        "    }\n"
        "}\n"
    ) % KEEP
    return "\n".join([_HEADER, win, _GADGET_STUB, _MAIN_E2E])


def build_e2e_fixture(variant: str) -> FixtureProgram:
    if variant == "arg1":
        source = _win_arg1_source()
        required = [{"position": 1, "value": 0x1337}]
        regs = ["rdi"]
    elif variant == "arg3":
        source = _win_arg3_source()
        required = [
            {"position": 1, "value": 0x1111},
            {"position": 2, "value": 0x2222},
            {"position": 3, "value": 0x3333},
        ]
        regs = ["rdi", "rsi", "rdx"]
    else:
        raise ValueError("unknown e2e fixture variant %r" % (variant,))
    return FixtureProgram(
        source=source,
        win_name="win",
        gadget_stub_name="gadget_stub",
        required_args=required,
        required_regs=regs,
        ret_offset=E2E_RET_OFFSET,
        detail={
            "fixture": "e2e_%s" % variant,
            "buffer_size": E2E_BUFFER_SIZE,
            "read_size": E2E_READ_SIZE,
            "alignment_note": (
                "entering win via this chain leaves rsp == 8 (mod 16) "
                "without an extra bare-ret alignment hop; confirmed by a "
                "local pwntools run that the aligned (use_align=True) "
                "chain reaches system(\"/bin/sh\") and the unaligned one "
                "SIGSEGVs inside glibc"
            ),
        },
    )


def build_abimix_fixture() -> FixtureProgram:
    # The double is stored to a volatile global so it is a *live* use of xmm0:
    # a purely dead ``(void)unused`` lets Ghidra's parameter recovery drop the
    # float formal altogether (verified live on 12.1.3: HighFunction then has a
    # single param ``key`` in RDI at slot 0 -> position 1), which would make
    # this fixture not exercise the mixed float/int ABI case it exists for.
    win = (
        "volatile double abimix_sink_d;\n"
        "\n"
        "%s\n"
        "void win(double unused, long key)\n"
        "{\n"
        "    abimix_sink_d = unused;\n"
        "    if (key == 0x4242) {\n"
        '        system("/bin/sh");\n'
        "    }\n"
        "}\n"
    ) % KEEP
    main = (
        "int main(void)\n"
        "{\n"
        "    char buf[8];\n"
        "    ssize_t n = read(0, buf, 8);\n"
        "    (void)n;\n"
        "    return 0;\n"
        "}\n"
    )
    source = "\n".join([_HEADER, win, main])
    return FixtureProgram(
        source=source,
        win_name="win",
        gadget_stub_name=None,
        # Ghidra's parameter ordinal is 0-indexed over the full signature
        # (double unused, long key), so key is slot 1 -> position 2; its
        # register is rdi (the first *integer*-class register), confirmed
        # via objdump: xmm0 carries `unused`, rdi carries `key`.
        required_args=[{"position": 2, "value": 0x4242}],
        required_regs=["rdi"],
        ret_offset=None,
        detail={"fixture": "abimix"},
    )
