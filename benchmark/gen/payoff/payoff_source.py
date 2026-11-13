"""Seeded C program synthesis for the payoff corpus.

One call to ``synthesize`` returns one program: the C text plus the facts about it
that the truth file needs (which function is the payoff, which are decoys, which are
referenced from ``main``, the constants an argument-checked payoff requires).

Every program has the same skeleton:

* ``main`` reads stdin into a fixed-size stack buffer with a read length larger than
  the buffer (the classic ret2win input path) and returns;
* a payoff function (positives only) that ``main`` never calls and nothing refers to;
* three decoys: a do-nothing function, a file-copy function over a path passed as a
  parameter, and a function that compares unrelated values (a global, or a local
  derived from one) against constants;
* a seeded number of filler functions.

Decoys and fillers are a seeded mix of referenced and unreferenced, so "nothing
calls it" does not identify the payoff, and the definition order is shuffled so the
address order does not either. Every candidate function carries
``__attribute__((noinline, used))``.

The source is independent of the build flags. It builds for ELF (gcc) as is, and for
PE (mingw) with ``-DBUILD_FOR_PE=1``, which only changes the headers.
"""

from __future__ import annotations

import dataclasses
import random
from typing import Dict, List, Optional, Sequence, Set, Tuple

from payoff_names import Namespace

SHAPES = ("exec", "file", "arg1", "arg3")
DECOY_KINDS = ("nop", "filecopy", "compare")
ROLES = (
    "payoff",
    "decoy_nop",
    "decoy_filecopy",
    "decoy_compare",
    "filler",
    "main",
)

# A shape's letter in the plan: (a) exec, (b) file, (c) one-argument check,
# (d) three-argument check.
SHAPE_LETTERS = {"exec": "a", "file": "b", "arg1": "c", "arg3": "d"}

KEEP = "__attribute__((noinline, used))"

HEADER = """\
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#ifdef BUILD_FOR_PE
#include <io.h>
#include <process.h>
#else
#include <unistd.h>
#endif
"""

EXECVE_COMMANDS = ("/bin/sh", "/bin/dash", "/bin/id", "/usr/bin/id", "/usr/bin/env")
SYSTEM_COMMANDS = ("/bin/sh", "/bin/id -a", "uname -a", "/usr/bin/whoami", "ls -la /")
FILE_PATHS = (
    "/etc/hostname",
    "/etc/os-release",
    "/proc/version",
    "/etc/issue",
    "/etc/hosts",
    "/proc/cpuinfo",
)
PARAM_TYPES = ("int", "unsigned int", "long", "unsigned long")
BUFFER_SIZES = (32, 48, 64, 80, 96, 128)
FILLER_KINDS = ("arith", "slen", "table", "clamp", "sum", "banner")

# Constants an argument check or a decoy comparison uses. Both are drawn from the
# same range, so a constant's magnitude does not separate them. All fit in 31 bits,
# so ELF and PE (where ``long`` is 32 bits) agree on the value.
CONST_RANGE = (0x1000, 0x7FFFFFFF)


@dataclasses.dataclass
class Function:
    name: str
    role: str
    proto: str
    text: str
    ret: str = "void"
    call: str = ""  # the call expression main uses if it references this function
    guarded: bool = False  # the call sits under a branch a normal run never takes
    called: bool = False  # main references it (always False for the payoff)


@dataclasses.dataclass
class Program:
    source: str
    functions: List[Function]  # in source (definition) order, main included
    globals_: List[str]
    shape: Optional[str]
    required_args: List[Dict[str, int]]
    detail: Dict[str, object]

    @property
    def names(self) -> List[str]:
        """Every generated identifier: functions (main excluded) and globals."""
        out = [f.name for f in self.functions if f.role != "main"]
        return sorted(out + self.globals_)


class _Consts:
    """Distinct constants from one stream, in a seeded decimal or hex spelling."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.seen: Set[int] = set()

    def draw(self) -> int:
        while True:
            value = self.rng.randrange(*CONST_RANGE)
            if value not in self.seen:
                self.seen.add(value)
                return value

    def spell(self, value: int) -> str:
        return hex(value) if self.rng.random() < 0.5 else str(value)

    def drawn(self) -> str:
        return self.spell(self.draw())


# ---------------------------------------------------------------------------
# Statement bodies


def _file_copy_lines(
    family: str, path_expr: str, ret_fail: str, ret_ok: str
) -> List[str]:
    """Open ``path_expr`` and copy it to stdout; ``ret_*`` are return statements."""
    if family == "stdio":
        return [
            'FILE *fp = fopen(%s, "rb");' % path_expr,
            "char tmp[128];",
            "size_t got;",
            "int total = 0;",
            "if (!fp)",
            "    %s" % ret_fail,
            "while ((got = fread(tmp, 1, sizeof tmp, fp)) > 0) {",
            "    fwrite(tmp, 1, got, stdout);",
            "    total += (int)got;",
            "}",
            "fclose(fp);",
            ret_ok,
        ]
    return [
        "int fd = open(%s, O_RDONLY);" % path_expr,
        "char tmp[128];",
        "int got;",
        "int total = 0;",
        "if (fd < 0)",
        "    %s" % ret_fail,
        "while ((got = read(fd, tmp, sizeof tmp)) > 0) {",
        "    write(1, tmp, got);",
        "    total += got;",
        "}",
        "close(fd);",
        ret_ok,
    ]


def _exec_lines(api: str, command: str) -> List[str]:
    quoted = '"%s"' % command
    if api == "execve":
        return [
            "char *av[2];",
            "av[0] = (char *)%s;" % quoted,
            "av[1] = NULL;",
            "execve(%s, (void *)av, NULL);" % quoted,
        ]
    return ["system(%s);" % quoted]


def _indent(lines: Sequence[str], depth: int = 1) -> List[str]:
    pad = "    " * depth
    return [pad + line if line else line for line in lines]


def _function(
    role: str,
    ret: str,
    name: str,
    params: str,
    body: Sequence[str],
    call: str = "",
    guarded: bool = False,
) -> Function:
    proto = "%s %s %s(%s);" % (KEEP, ret, name, params)
    head = "%s %s %s(%s)" % (KEEP, ret, name, params)
    text = "\n".join([head, "{", *_indent(body), "}"])
    return Function(name, role, proto, text, ret, call, guarded)


# ---------------------------------------------------------------------------
# Payoff


def _payoff(
    rng: random.Random, ns: Namespace, consts: _Consts, shape: str, family: str
) -> Tuple[Function, List[Dict[str, int]], Dict[str, object]]:
    action = {"exec": "exec", "file": "file"}.get(shape) or rng.choice(("exec", "file"))
    detail: Dict[str, object] = {"action": action}
    if action == "exec":
        api = rng.choice(("execve", "system"))
        commands = EXECVE_COMMANDS if api == "execve" else SYSTEM_COMMANDS
        command = rng.choice(commands)
        body = _exec_lines(api, command)
        detail.update(exec_api=api, command=command, path=None)
    else:
        path = rng.choice(FILE_PATHS)
        body = _file_copy_lines(family, '"%s"' % path, "return;", "return;")
        detail.update(exec_api=None, command=None, path=path)
    name = ns.fresh()
    required: List[Dict[str, int]] = []
    if shape in ("exec", "file"):
        detail.update(arg_style=None, param_types=None)
        func = _function("payoff", "void", name, "void", body)
        return func, required, detail
    count = 1 if shape == "arg1" else 3
    types = [rng.choice(PARAM_TYPES) for _ in range(count)]
    letters = ["a", "b", "c"][:count]
    values = [consts.draw() for _ in range(count)]
    spelled = [consts.spell(v) for v in values]
    style = rng.choice(("and", "nest", "early"))
    params = ", ".join("%s %s" % (t, name_) for t, name_ in zip(types, letters))
    tests = ["%s == %s" % (a, s) for a, s in zip(letters, spelled)]
    if style == "and":
        lines = ["if (%s) {" % " && ".join(tests), *_indent(body), "}"]
    elif style == "nest":
        lines = []
        for depth, test in enumerate(tests):
            lines.extend(_indent(["if (%s) {" % test], depth))
        lines.extend(_indent(body, count))
        for depth in range(count - 1, -1, -1):
            lines.extend(_indent(["}"], depth))
    else:
        lines = []
        for a, s in zip(letters, spelled):
            lines.extend(["if (%s != %s)" % (a, s), "    return;"])
        lines.extend(body)
    required = [{"position": i + 1, "value": v} for i, v in enumerate(values)]
    detail.update(arg_style=style, param_types=types)
    return _function("payoff", "void", name, params, lines), required, detail


# ---------------------------------------------------------------------------
# Decoys


def _decoy_nop(rng: random.Random, ns: Namespace) -> Function:
    count = rng.randint(0, 2)
    types = [rng.choice(("int", "long")) for _ in range(count)]
    params = ", ".join("%s p%d" % (t, i) for i, t in enumerate(types)) or "void"
    body = ["(void)p%d;" % i for i in range(count)] or ["/* nothing to do */"]
    name = ns.fresh()
    call = "%s(%s)" % (name, ", ".join("0" for _ in types))
    return _function("decoy_nop", "void", name, params, body, call)


def _decoy_filecopy(rng: random.Random, ns: Namespace, family: str) -> Function:
    name = ns.fresh()
    body = _file_copy_lines(family, "path", "return -1;", "return total;")
    call = '%s("/dev/null")' % name
    return _function(
        "decoy_filecopy", "int", name, "const char *path", body, call, guarded=True
    )


def _decoy_compare(
    rng: random.Random, ns: Namespace, consts: _Consts
) -> Tuple[Function, str, str]:
    """Unrelated comparisons: a global, and a local derived from the global."""
    gname = ns.fresh()
    gdef = "unsigned long %s = %sUL;" % (gname, consts.drawn())
    ops = ("==", "!=", "<", ">")
    body = [
        "int r = 0;",
        "unsigned long v = %s * %dUL + %dUL;"
        % (gname, rng.randint(2, 9), rng.randint(1, 99)),
        "int t = (int)(%s >> %d) ^ %s;" % (gname, rng.randint(1, 5), consts.drawn()),
    ]
    probes = ["v", gname, "t"]
    for i in range(rng.randint(2, 4)):
        subject = rng.choice(probes)
        cast = "(int)" if subject == "t" else ""
        test = "%s%s %s %s" % (cast, subject, rng.choice(ops), consts.drawn())
        body.extend(["if (%s)" % test, "    r |= %d;" % (1 << i)])
    body.append("return r;")
    name = ns.fresh()
    func = _function("decoy_compare", "int", name, "void", body, "%s()" % name)
    return func, gdef, gname


# ---------------------------------------------------------------------------
# Fillers


def _filler(
    rng: random.Random, ns: Namespace, kind: str
) -> Tuple[Function, List[Tuple[str, str]]]:
    """A filler function and the (definition, name) of any global it needs."""
    name = ns.fresh()
    globals_: List[Tuple[str, str]] = []
    k1, k2 = rng.randint(3, 97), rng.randint(0x10, 0xFFFF)
    guarded = False
    if kind == "arith":
        body = [
            "long r = a;",
            "int i;",
            "for (i = 0; i < (int)(b & 7); i++)",
            "    r = r * %d + i;" % k1,
            "return r ^ %d;" % k2,
        ]
        ret, params = "long", "long a, long b"
        call = "%s(%d, %d)" % (name, rng.randint(1, 50), rng.randint(1, 50))
    elif kind == "slen":
        body = [
            "unsigned long n = 0;",
            "while (s[n])",
            "    n++;",
            "return n + %d;" % (k1 % 7),
        ]
        ret, params = "unsigned long", "const char *s"
        call = '%s("%s")' % (name, ns.phrase(1))
    elif kind == "table":
        table = ns.fresh()
        values = ", ".join(str(rng.randint(1, 999)) for _ in range(8))
        globals_.append(("static const int %s[8] = { %s };" % (table, values), table))
        body = ["return %s[i & 7] + %d;" % (table, k1)]
        ret, params = "int", "int i"
        call = "%s(%d)" % (name, rng.randint(0, 20))
    elif kind == "clamp":
        body = [
            "if (v < lo)",
            "    return lo;",
            "if (v > hi)",
            "    return hi;",
            "return v;",
        ]
        ret, params = "int", "int v, int lo, int hi"
        call = "%s(%d, %d, %d)" % (
            name,
            rng.randint(0, 99),
            rng.randint(0, 20),
            rng.randint(21, 60),
        )
    elif kind == "sum":
        body = [
            "unsigned int s = %d;" % k2,
            "int i;",
            "for (i = 0; i < len; i++)",
            "    s = s * 31 + p[i];",
            "return s;",
        ]
        ret, params = "unsigned int", "const unsigned char *p, int len"
        word = ns.phrase(1)
        call = '%s((const unsigned char *)"%s", %d)' % (name, word, len(word))
    else:  # banner: writes a constant to stdout, so a normal run never calls it
        body = ['puts("%s");' % ns.phrase(2)]
        ret, params = "void", "void"
        call = "%s()" % name
        guarded = True
    func = _function("filler", ret, name, params, body, call, guarded)
    return func, globals_


# ---------------------------------------------------------------------------
# Whole program


def synthesize(rng: random.Random, ns: Namespace, shape: Optional[str]) -> Program:
    """Build one program. ``shape`` None makes a negative (no payoff function)."""
    if shape is not None and shape not in SHAPES:
        raise ValueError("unknown shape %r" % (shape,))
    family = rng.choice(("stdio", "posix"))
    consts = _Consts(rng)
    buffer_size = rng.choice(BUFFER_SIZES)
    read_size = buffer_size * 2 + rng.choice((0, 16, 32, 64))

    functions: List[Function] = []
    globals_text: List[str] = []
    globals_names: List[str] = []
    required: List[Dict[str, int]] = []
    detail: Dict[str, object] = {
        "io_family": family,
        "buffer_size": buffer_size,
        "read_size": read_size,
        "action": None,
        "exec_api": None,
        "command": None,
        "path": None,
        "arg_style": None,
        "param_types": None,
    }
    if shape is not None:
        payoff, required, payoff_detail = _payoff(rng, ns, consts, shape, family)
        detail.update(payoff_detail)
        functions.append(payoff)

    decoys = {
        "nop": _decoy_nop(rng, ns),
        "filecopy": _decoy_filecopy(rng, ns, family),
    }
    compare, gdef, gname = _decoy_compare(rng, ns, consts)
    decoys["compare"] = compare
    globals_text.append(gdef)
    globals_names.append(gname)
    functions.extend(decoys[k] for k in DECOY_KINDS)
    # At least one decoy is referenced and at least one is not.
    referenced = set(rng.sample(DECOY_KINDS, rng.choice((1, 2))))
    for kind in DECOY_KINDS:
        decoys[kind].called = kind in referenced

    fillers: List[Function] = []
    for _ in range(rng.randint(3, 9)):
        func, extra = _filler(rng, ns, rng.choice(FILLER_KINDS))
        func.called = rng.random() < 0.5
        for text, name in extra:
            globals_text.append(text)
            globals_names.append(name)
        fillers.append(func)
    # At least one filler referenced and one not, so neither is a tell.
    if all(f.called for f in fillers):
        fillers[rng.randrange(len(fillers))].called = False
    elif not any(f.called for f in fillers):
        fillers[rng.randrange(len(fillers))].called = True
    functions.extend(fillers)

    main = Function("main", "main", "", _main_text(functions, buffer_size, read_size))
    functions.append(main)
    rng.shuffle(functions)
    rng.shuffle(globals_text)

    parts = [HEADER, *globals_text, "", *[f.proto for f in functions if f.proto], ""]
    parts.append("\n\n".join(f.text for f in functions))
    source = "\n".join(parts) + "\n"
    return Program(source, functions, sorted(globals_names), shape, required, detail)


def _main_text(functions: Sequence[Function], buffer_size: int, read_size: int) -> str:
    def statement(func: Function, pad: str) -> str:
        if func.ret == "void":
            return "%s%s;" % (pad, func.call)
        return "%sacc += (long)%s;" % (pad, func.call)

    plain = [f for f in functions if f.called and not f.guarded]
    guarded = [f for f in functions if f.called and f.guarded]
    lines = [
        "int main(int argc, char **argv)",
        "{",
        "    char buf[%d];" % buffer_size,
        "    long n;",
        "    long acc = 0;",
        "",
        "    (void)argc;",
        "    (void)argv;",
        "    n = read(0, buf, %d);" % read_size,
    ]
    lines.extend(statement(f, "    ") for f in plain)
    if guarded:
        lines.append("    if (n < 0) {")
        lines.extend(statement(f, "        ") for f in guarded)
        lines.append("    }")
    lines.extend(["    (void)acc;", "    return 0;", "}"])
    return "\n".join(lines)
