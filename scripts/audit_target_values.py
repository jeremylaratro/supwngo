#!/usr/bin/env python3
"""Inventory of hardcoded target values in the supwngo product package.

Directive W (plan: docs/plans/2026-11-13-retire-hardcoded-target-values-plan.md,
section 2) retires every target-specific value the product acts on: win-function
names, guessed comparison constants, platform flag patterns. This script is the
mechanical half of that inventory. It runs pinned AST searches over
``supwngo/**/*.py`` (the product package only: not tests, not benchmark, not
scripts) and reports every site, with a class:

* ``A``  name-based payoff selection in product code: a symbol-name list, a
  constant-keyed lookup in a symbol table, a name compared to a constant.
* ``A'`` the same name dependence inside a generated-script or payload template
  string.
* ``B``  integer collections used as comparison or argument candidates.
* ``C``  success-detection or flag-pattern strings and regexes.

Each hit also carries a ``kind`` naming which of the six pinned searches matched:

====================  =====  ==================================================
kind                  class  search
====================  =====  ==================================================
``name_list``         A      1. a collection of payoff-like name strings
``symtab_subscript``  A      2. ``symbols["x"]``
``symtab_get``        A      2. ``symbols.get("x")``
``symtab_attr``       A      2. ``elf.sym.x``
``symtab_arg``        A      2. a constant name passed beside a symbol table, or
                             to a symbol-lookup helper
``name_in``           A      3. ``name in {...}``, ``"x" in funcs``
``name_eq``           A      3. ``name == "x"``
``name_startswith``   A      3. ``name.startswith("x")``
``int_list``          B      4. an integer collection bound to a name that is
                             later iterated or tested
``int_list_use``      B      4. an integer collection iterated or tested
``int_to_bytes``      B      4. ``(1).to_bytes(...)``, a literal as the value
``flag_shape``        C      5. a string or regex constant containing a
                             ``prefix{`` flag shape
``success_words``     C      5. a collection of success words
``success_compare``   C      5. a success word tested against program output
``template_symbol``   A'     6. a symbol-table lookup inside a template string
``template_name``     A'     6. a payoff name in a compare or list inside a
                             template string
====================  =====  ==================================================

The scan is broad on purpose: it reports a site whether or not the name it
holds is a payoff, and the plan closes every entry as ``migrated`` or
``allowed`` with a justification. It has two pinned exemptions, both narrow, so
the denominator stays reviewable:

* a symbol table rooted at ``libc`` (``LIBC_ROOTS``): libc's names are the C
  library's ABI, not values of the program under analysis;
* a name that is a libc, loader, kernel or C-language name (``UNIVERSAL_NAMES``
  and ``UNIVERSAL_PREFIXES``): every program shares it, so looking it up names
  no particular target.

String searches match the *shape* ``[A-Za-z0-9_]+\\{`` (``htb{``, ``flag{``,
``(?:a|b)\\{`` in a regex); no platform token is needed to find one.

Usage (always with ``python3 -I``)::

    python3 -I scripts/audit_target_values.py          # current hits, JSON
    python3 -I scripts/audit_target_values.py --regen  # rewrite the baseline

``--regen`` is for the W-0 merge base only. After W-0 the baseline is immutable
except for the closure status of an entry (plan section 2).

Entry IDs are ``W-<index>``, four digits, assigned in ``(path, line, kind,
class)`` order. That order depends only on frozen fields, so an ID never moves.
Each hit also carries an ``anchor``, a hash of its normalised source line, so a
later edit that only shifts lines can still be matched to its entry.
"""

from __future__ import annotations

import argparse
import ast
import functools
import hashlib
import json
import re
import subprocess
import sys
import tokenize
from collections import defaultdict
from pathlib import Path
from typing import (
    Dict,
    FrozenSet,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "supwngo"
BASELINE_PATH = REPO_ROOT / "tests" / "data" / "target_values_baseline.json"

SCANNER_VERSION = 1
CLASSES = ("A", "A'", "B", "C")
STATUSES = ("open", "migrated", "allowed")
# kind -> class: the pinned classification of each search (see the module
# docstring). A hit whose class disagrees with its kind is a scanner bug.
KIND_CLASS = {
    "name_list": "A",
    "symtab_subscript": "A",
    "symtab_get": "A",
    "symtab_attr": "A",
    "symtab_arg": "A",
    "name_in": "A",
    "name_eq": "A",
    "name_startswith": "A",
    "int_list": "B",
    "int_list_use": "B",
    "int_to_bytes": "B",
    "flag_shape": "C",
    "success_words": "C",
    "success_compare": "C",
    "template_symbol": "A'",
    "template_name": "A'",
}

# ---------------------------------------------------------------------------
# Pinned lexicons. Each one is part of a search definition: changing one
# changes the denominator, so it is a baseline-regeneration event.

# Words that make a string look like a payoff-function name. Matched on the
# lowercase word tokens of a string (``get_flag`` -> ``get``, ``flag``).
PAYOFF_TOKENS = frozenset(
    {
        "win",
        "winner",
        "flag",
        "shell",
        "backdoor",
        "secret",
        "admin",
        "pwn",
        "hack",
        "vuln",
        "vulnerable",
    }
)

# Names so specific to a "call this to win" function that an exact compare
# against one is a hit whatever it is compared to.
STRICT_PAYOFF_NAMES = frozenset(
    {
        "win",
        "winner",
        "get_flag",
        "getflag",
        "print_flag",
        "printflag",
        "read_flag",
        "readflag",
        "show_flag",
        "give_flag",
        "give_shell",
        "giveshell",
        "spawn_shell",
        "spawnshell",
        "get_shell",
        "getshell",
        "backdoor",
    }
)

# Identifier words that mean "this expression holds a symbol or function name"
# (``func_name``, ``sym``, ``funcs``) ...
SYMBOL_TOKENS = frozenset(
    {
        "sym",
        "syms",
        "symbol",
        "symbols",
        "symtab",
        "func",
        "funcs",
        "function",
        "functions",
        "fn",
        "fname",
        "callee",
        "callees",
        "got",
        "plt",
        "routine",
    }
)
# ... and the subset that names a table keyed by symbol name.
TABLE_TOKENS = frozenset(
    {"symbols", "symtab", "syms", "functions", "funcs", "got", "plt"}
)
# Attributes of a symbol-like object that hold its name.
NAME_ATTRS = frozenset({"name", "symbol", "sym", "func", "fname", "function"})
# Words in a callee name that make it a symbol-lookup helper.
LOOKUP_TOKENS = frozenset({"symbol", "sym", "function", "func", "lookup", "resolve"})

# Identifier words that mean "this expression holds program output".
OUTPUT_TOKENS = frozenset(
    {
        "output",
        "out",
        "stdout",
        "stderr",
        "result",
        "text",
        "resp",
        "response",
        "recv",
        "banner",
        "data",
        "buf",
        "reply",
        "received",
        "log",
        "transcript",
    }
)

# Whole-string success indicators (compared after lowercasing and stripping
# trailing punctuation).
SUCCESS_WORDS = frozenset(
    {
        "win",
        "you win",
        "you won",
        "success",
        "successful",
        "congratulations",
        "congrats",
        "pwned",
        "flag",
        "ctf",
        "htb",
    }
)

# Pinned exemption 1: symbol-table roots that are libc, not the target.
LIBC_ROOTS = frozenset({"libc", "libc_elf", "libc_obj", "libcelf"})

# Pinned exemption 2: names every C program shares.
UNIVERSAL_NAMES = frozenset(
    {
        # C language, entry points and loader/runtime bookkeeping
        "if", "while", "for", "switch", "return", "sizeof", "main", "_start",
        "_init", "_fini", "init", "fini", "environ", "stdout", "stdin", "stderr",
        "atexit", "on_exit", "setvbuf", "vtable", "dtor_idx", "completed",
        "_text", "startup_64",
        # stdio
        "puts", "printf", "fprintf", "sprintf", "snprintf", "dprintf", "vprintf",
        "vfprintf", "vsnprintf", "gets", "fgets", "fputs", "fputc", "putc",
        "putchar", "getc", "getchar", "fgetc", "scanf", "fscanf", "sscanf",
        "fopen", "fdopen", "freopen", "fread", "fwrite", "fclose", "fflush",
        "fseek", "ftell", "rewind", "perror", "getline", "getdelim", "tmpfile",
        # strings and memory
        "strcpy", "strncpy", "strcat", "strncat", "strlen", "strcmp", "strncmp",
        "strchr", "strrchr", "strstr", "strdup", "strtok", "strtol", "strtoul",
        "strcasecmp", "strncasecmp", "strlcpy", "strlcat", "strnlen", "strspn",
        "strcspn", "strpbrk", "stpcpy", "memcpy", "memmove", "memset", "memcmp",
        "memchr", "memcmp", "bcmp", "bcopy", "bzero", "memccpy", "mempcpy",
        "atoi", "atol", "atoll", "atof", "malloc", "calloc", "realloc",
        "reallocarray", "free", "memalign", "valloc", "aligned_alloc",
        "posix_memalign", "alloca", "sscanf",
        # files and processes
        "open", "openat", "creat", "close", "read", "write", "pread", "pwrite",
        "lseek", "stat", "lstat", "fstat", "access", "unlink", "unlinkat",
        "rename", "mkdir", "rmdir", "chmod", "chown", "readlink", "symlink",
        "link", "realpath", "dup", "dup2", "pipe", "fork", "vfork", "wait",
        "waitpid", "kill", "exit", "_exit", "abort", "system", "popen", "execve",
        "execv", "execl", "execle", "execlp", "execvp", "execvpe", "getenv",
        "setenv", "putenv", "secure_getenv", "issetugid", "getuid", "geteuid",
        "getgid", "setuid", "setgid", "seteuid", "setreuid", "getpid", "alarm",
        "signal", "sigaction", "sigprocmask", "raise", "sleep", "usleep",
        "nanosleep", "select", "poll", "mmap", "munmap", "mprotect", "brk",
        "sbrk", "syscall", "ptrace", "ioctl", "fcntl", "chdir", "getcwd",
        "dlopen", "dlsym", "dlclose", "crypt", "sendfile", "mkstemp", "mktemp",
        "tmpnam", "opendir", "readdir", "closedir", "mkfifo", "umask",
        # sockets
        "socket", "connect", "bind", "listen", "accept", "send", "recv",
        "sendto", "recvfrom", "shutdown", "setsockopt", "getsockopt",
        # time and randomness
        "time", "rand", "srand", "random", "srandom", "drand48", "srand48",
        "lrand48", "clock", "gettimeofday", "clock_gettime", "localtime",
        "gmtime", "mktime", "strftime", "getrandom",
        # threads
        "pthread_create", "pthread_join", "pthread_mutex_lock",
        "pthread_mutex_unlock", "pthread_mutex_init", "pthread_cond_wait",
        "pthread_cond_signal", "thrd_create",
        # libc/loader/runtime internals commonly looked up by exploit code
        "_IO_list_all", "_IO_2_1_stdout_", "_IO_2_1_stdin_", "_IO_2_1_stderr_",
        "_IO_str_jumps", "_IO_wfile_jumps", "_vtv_verify_vtable",
        "__VLTRegisterPair", "scudo", "hwasan",
        # kernel API names used by the kernel exploit modules
        "prepare_kernel_cred", "commit_creds", "init_cred", "find_task_by_vpid",
        "modprobe_path", "core_pattern", "swapgs", "iretq", "native_write_cr4",
        "native_write_cr0", "kallsyms_lookup_name", "init_task", "current_task",
        "msleep", "printk", "kmalloc", "kfree", "copy_from_user", "copy_to_user",
        # 64-bit and checked variants, C runtime stubs, and more libc
        "open64", "creat64", "fopen64", "freopen64", "stat64", "lstat64",
        "fstat64", "pread64", "pwrite64", "mmap64", "readdir64", "tmpfile64",
        "openat64", "euidaccess", "eaccess", "canonicalize_file_name", "index",
        "rindex", "strcasestr", "lchown", "fchown", "fchmod", "truncate",
        "truncate64", "ftruncate", "vsprintf", "strtoull", "strtoll", "gets_s",
        "frame_dummy", "register_tm_clones", "deregister_tm_clones",
        "call_weak_fn", "wmemcpy", "wcscpy", "fgetws", "fputws", "execl",
        "pclose", "memfd_create", "prctl", "seccomp", "syslog", "vsyslog",
    }
)  # fmt: skip
UNIVERSAL_PREFIXES = ("__", "_IO_", "_dl_", "pthread_", "_ITM_")
# Prefixes that decompilers and linkers put on a name; they say nothing about
# the program.
TOOL_PREFIXES = ("sub_", "fun_", "loc_", "func_", "j_", "_", "0x", "@", ".")

ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# ``prefix{`` where the prefix is a word (``htb{``, ``flag\{`` in a regex) or a
# closing group, optionally followed by a ``\s`` class (``(flag|ctf)\s*\{``).
# Rejected afterwards when the brace opens a regex quantifier (``x{2,3}``) or a
# format field (``0x{addr:x}``).
FLAG_SHAPE_RE = re.compile(
    r"(?:(?:[A-Za-z0-9_]+|(?<!\\)\))(?:\\+s[*+?]?)?\\+|[A-Za-z0-9_]+)\{"
)
_QUANTIFIER_RE = re.compile(r"\d+(?:,\d*)?\}|,\d+\}")
_FORMAT_FIELD_RE = re.compile(
    r"(?:[A-Za-z_][\w.]*(?:\[[^\]]*\])?)?(?:![rsa])?(?::[^{}]*)?\}"
)

_TABLES = "symbols|symtab|syms|sym|functions|funcs|got|plt"
TEMPLATE_SYMBOL_RE = re.compile(
    r"\b(?:" + _TABLES + r")\s*(?:\[\s*|\.get\s*\(\s*)\\?(?P<q>['\"])"
    r"(?P<name>[A-Za-z_]\w*)(?P=q)|\.sym\.(?P<attr>[A-Za-z_]\w*)"
)
_STRICT_ALT = "|".join(sorted(STRICT_PAYOFF_NAMES))
TEMPLATE_NAME_RE = re.compile(
    r"(?:[\[({,]\s*|==\s*|!=\s*|\bin\s+)\\?['\"](?:" + _STRICT_ALT + r")\\?['\"]"
    r"|\\?['\"](?:" + _STRICT_ALT + r")\\?['\"]\s*(?:[\])},]|==|!=|\bin\b)"
)
_LIBC_BEFORE_RE = re.compile(r"\blibc\w*\s*\.?\s*$")
_DELIMITED_WORD_RE = re.compile(r"\s*[rbfuRBFU]*(['\"])\w+\1\s*,?")

_TEXT_METHODS = frozenset(
    {"lower", "upper", "strip", "lstrip", "rstrip", "decode", "encode", "casefold"}
)
_COLLECTION_WRAPPERS = frozenset({"set", "frozenset", "tuple", "list", "sorted"})
_PREFIX_METHODS = frozenset({"startswith", "endswith"})
_EQUALITY_OPS = (ast.In, ast.NotIn, ast.Eq, ast.NotEq)
# The node types the searches iterate; everything else is not indexed.
_INDEXED_TYPES = frozenset(
    {
        ast.Subscript,
        ast.Attribute,
        ast.Call,
        ast.Compare,
        ast.Name,
        ast.For,
        ast.AsyncFor,
        ast.comprehension,
        ast.Assign,
        ast.AnnAssign,
        ast.List,
        ast.Tuple,
        ast.Set,
        ast.Dict,
    }
)


class Hit(NamedTuple):
    """One site. ``key`` is the identity the baseline freezes."""

    path: str
    line: int
    cls: str
    kind: str
    anchor: str  # hash of the normalised source line; survives line drift
    text: str  # the stripped source line, for humans; not part of any identity

    @property
    def key(self) -> str:
        return f"{self.cls}:{self.path}:{self.line}:{self.kind}"

    def as_json(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "class": self.cls,
            "kind": self.kind,
            "anchor": self.anchor,
            "text": self.text,
        }


# ---------------------------------------------------------------------------
# Small helpers


@functools.lru_cache(maxsize=None)
def _tokens(identifier: str) -> FrozenSet[str]:
    """Lowercase word tokens of a snake_case or camelCase identifier."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", identifier)
    return frozenset(t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t)


def is_universal(name: str) -> bool:
    return name in UNIVERSAL_NAMES or name.startswith(UNIVERSAL_PREFIXES)


def _is_universal_prefix(prefix: str) -> bool:
    """A ``startswith`` argument that every program's names share."""
    return (
        prefix.startswith(TOOL_PREFIXES)
        or is_universal(prefix)
        or any(n.startswith(prefix) for n in UNIVERSAL_NAMES)
    )


def _is_flag_shape(text: str) -> bool:
    if "{" not in text:
        return False
    for match in FLAG_SHAPE_RE.finditer(text):
        rest = text[match.end() :].lstrip("{")
        if _QUANTIFIER_RE.match(rest) or _FORMAT_FIELD_RE.match(rest):
            continue
        return True
    return False


def _is_success_word(text: str) -> bool:
    return text.strip().lower().rstrip(":!. ") in SUCCESS_WORDS


def _targetish(names: Iterable[str]) -> bool:
    """Does any of these constants name something target-specific?"""
    return any(
        ID_RE.match(n) and len(n) > 1 and not is_universal(n) for n in names
    ) or any(n.lower() in STRICT_PAYOFF_NAMES for n in names)


def _const_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("latin-1")
    return None


def _const_int(node: ast.AST) -> Optional[int]:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        inner = _const_int(node.operand)
        if inner is None:
            return None
        return -inner if isinstance(node.op, ast.USub) else inner
    if isinstance(node, ast.Constant):
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value
    return None


def _slice_key(node: ast.Subscript) -> Optional[str]:
    key = node.slice
    if type(key).__name__ == "Index":  # Python 3.8
        key = key.value  # type: ignore[attr-defined]
    return _const_str(key)


def _wrapper_inner(node: ast.AST) -> Optional[ast.AST]:
    """``frozenset({...})`` and friends are the collection they wrap."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _COLLECTION_WRAPPERS
        and len(node.args) == 1
        and not node.keywords
    ):
        return node.args[0]
    return None


def _literal_elements(node: ast.AST) -> Optional[List[ast.AST]]:
    inner = _wrapper_inner(node)
    while inner is not None:
        node = inner
        inner = _wrapper_inner(node)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return list(node.elts)
    if isinstance(node, ast.Dict):
        return [k for k in node.keys if k is not None]
    return None


def _string_elements(node: ast.AST) -> Optional[List[str]]:
    elts = _literal_elements(node)
    if not elts:
        return None
    strs = [s for s in (_const_str(e) for e in elts) if s is not None]
    return strs if strs and len(strs) * 2 >= len(elts) else None


def _int_elements(node: ast.AST) -> Optional[List[int]]:
    if isinstance(node, ast.Dict):
        return None
    elts = _literal_elements(node)
    if not elts or len(elts) < 2:
        return None
    ints = [_const_int(e) for e in elts]
    if any(i is None for i in ints):
        return None
    return [i for i in ints if i is not None]


def _terminal(node: ast.AST) -> Optional[str]:
    """The identifier an expression ends in (``self.binary.symbols`` -> symbols)."""
    while True:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Subscript):
            node = node.value
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in _TEXT_METHODS:
                node = node.func.value
            else:
                node = node.func
        else:
            return None


def _root(node: ast.AST) -> Optional[str]:
    """The leftmost name of an attribute chain (``libc.symbols`` -> libc)."""
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _unwrap_text(node: ast.AST) -> ast.AST:
    while (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _TEXT_METHODS
    ):
        node = node.func.value
    return node


def _is_table(node: ast.AST) -> bool:
    """Is this expression a table keyed by symbol name (not one symbol)?"""
    if isinstance(node, ast.Name):
        return bool(_tokens(node.id) & TABLE_TOKENS)
    if isinstance(node, ast.Attribute):
        return node.attr == "sym" or bool(_tokens(node.attr) & TABLE_TOKENS)
    return False


def _normalise_line(text: str) -> str:
    return " ".join(text.split())


def _anchor(text: str) -> str:
    digest = hashlib.sha1(_normalise_line(text).encode("utf-8", "replace"))
    return digest.hexdigest()[:10]


def _mask_fields(raw: str) -> str:
    """Blank the replacement fields of an f-string; ``{{`` stays literal."""
    out: List[str] = []
    depth = 0
    i = 0
    while i < len(raw):
        ch = raw[i]
        if depth == 0:
            if ch == "{" and raw[i + 1 : i + 2] == "{":
                out.append("{{")
                i += 2
                continue
            if ch == "{":
                depth = 1
                out.append(" ")
            else:
                out.append(ch)
        else:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            out.append(" ")
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Per-module analysis


class _Module:
    """One parsed module and the cross-reference tables the searches share."""

    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.lines = source.split("\n")
        self.tree = ast.parse(source, filename=path)
        self.parents: Dict[int, ast.AST] = {}
        self.by_type: Dict[type, List[ast.AST]] = defaultdict(list)
        self.strings: List[ast.AST] = []
        self.hits: Dict[str, Hit] = {}
        self._uses: Optional[Dict[str, List[ast.AST]]] = None
        self._bindings: Optional[Dict[str, ast.AST]] = None
        self._symbol_vars: Dict[int, Set[str]] = defaultdict(set)
        self._index()
        self._find_symbol_vars()

    # -- indexing -----------------------------------------------------------

    def _index(self) -> None:
        """One pass: parents, nodes by type, and the outermost string nodes."""
        wanted = _INDEXED_TYPES
        by_type, parents, strings = self.by_type, self.parents, self.strings
        stack: List[Tuple[ast.AST, bool]] = [(self.tree, False)]
        while stack:
            node, in_fstring = stack.pop()
            kind = type(node)
            if kind in wanted:
                by_type[kind].append(node)
            joined = kind is ast.JoinedStr
            if not in_fstring:
                if joined:
                    strings.append(node)
                elif kind is ast.Constant and isinstance(
                    node.value,
                    (str, bytes),  # type: ignore[attr-defined]
                ):
                    # A bare string statement is prose (docstring), not data.
                    if not isinstance(parents.get(id(node)), ast.Expr):
                        strings.append(node)
            nested = in_fstring or joined
            for field in node._fields:
                value = getattr(node, field, None)
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, ast.AST):
                            parents[id(item)] = node
                            stack.append((item, nested))
                elif isinstance(value, ast.AST):
                    parents[id(value)] = node
                    stack.append((value, nested))

    def nodes_of(self, *types: type) -> List[ast.AST]:
        out: List[ast.AST] = []
        for kind in types:
            out.extend(self.by_type.get(kind, []))
        return out

    def parent(self, node: ast.AST) -> Optional[ast.AST]:
        return self.parents.get(id(node))

    def scope(self, node: ast.AST) -> ast.AST:
        cur: Optional[ast.AST] = node
        while cur is not None:
            if isinstance(
                cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)
            ):
                return cur
            cur = self.parent(cur)
        return self.tree

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1]
        return ""

    def add(self, line: int, cls: str, kind: str) -> None:
        assert KIND_CLASS[kind] == cls, (kind, cls)
        text = self.line_text(line)
        hit = Hit(
            self.path, line, cls, kind, _anchor(text), _normalise_line(text)[:110]
        )
        self.hits.setdefault(hit.key, hit)

    # -- symbol-name variables ---------------------------------------------

    def _find_symbol_vars(self) -> None:
        """Names bound by iterating something that holds symbols or functions."""
        for node in self.nodes_of(ast.For, ast.AsyncFor, ast.comprehension):
            target, iterable = node.target, node.iter  # type: ignore[attr-defined]
            if any(
                _tokens(sub.id if isinstance(sub, ast.Name) else sub.attr)
                & SYMBOL_TOKENS
                for sub in ast.walk(iterable)
                if isinstance(sub, (ast.Name, ast.Attribute))
            ):
                names = self._symbol_vars[id(self.scope(target))]
                names.update(
                    sub.id for sub in ast.walk(target) if isinstance(sub, ast.Name)
                )

    def symbolish(self, node: ast.AST) -> bool:
        """Does this expression hold a symbol or function name?"""
        node = _unwrap_text(node)
        if isinstance(node, ast.Name):
            return bool(_tokens(node.id) & SYMBOL_TOKENS) or (
                node.id in self._symbol_vars.get(id(self.scope(node)), ())
            )
        if isinstance(node, ast.Attribute):
            if _tokens(node.attr) & SYMBOL_TOKENS:
                return True
            return node.attr in NAME_ATTRS and self.symbolish(node.value)
        return False

    @staticmethod
    def outputish(node: ast.AST) -> bool:
        ident = _terminal(_unwrap_text(node))
        return ident is not None and bool(_tokens(ident) & OUTPUT_TOKENS)

    # -- searches 2 and 3: names against constants -------------------------

    def search_names(self) -> None:
        for node in self.nodes_of(ast.Subscript):
            self._subscript(node)  # type: ignore[arg-type]
        for node in self.nodes_of(ast.Attribute):
            self._sym_attr(node)  # type: ignore[arg-type]
        for node in self.nodes_of(ast.Call):
            self._call(node)  # type: ignore[arg-type]
        for node in self.nodes_of(ast.Compare):
            self._compare(node)  # type: ignore[arg-type]

    @staticmethod
    def _libc_table(table: ast.AST) -> bool:
        return _root(table) in LIBC_ROOTS

    def _subscript(self, node: ast.Subscript) -> None:
        key = _slice_key(node)
        if (
            key
            and isinstance(node.ctx, ast.Load)
            and _is_table(node.value)
            and not self._libc_table(node.value)
            and not is_universal(key)
        ):
            self.add(node.lineno, "A", "symtab_subscript")

    def _sym_attr(self, node: ast.Attribute) -> None:
        inner = node.value
        if isinstance(inner, ast.Attribute) and inner.attr == "sym":
            if not self._libc_table(inner) and not is_universal(node.attr):
                self.add(node.lineno, "A", "symtab_attr")

    def _call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr == "get" and node.args:
                key = _const_str(node.args[0])
                if (
                    key
                    and _is_table(func.value)
                    and not self._libc_table(func.value)
                    and not is_universal(key)
                ):
                    self.add(node.lineno, "A", "symtab_get")
                return
            if func.attr in _PREFIX_METHODS:
                self._prefix_call(node, func)
                return
            if func.attr == "to_bytes":
                if _const_int(func.value) is not None:
                    self.add(node.lineno, "B", "int_to_bytes")
                return
        names = [
            s
            for s in (_const_str(a) for a in node.args)
            if s is not None and ID_RE.match(s) and len(s) > 1 and not is_universal(s)
        ]
        callee = _terminal(func)
        if not names or callee is None or _root(func) in LIBC_ROOTS:
            return
        others = list(node.args) + [k.value for k in node.keywords]
        has_table = any(_is_table(a) for a in others)
        if has_table or (_tokens(callee) & LOOKUP_TOKENS):
            self.add(node.lineno, "A", "symtab_arg")

    def _prefix_call(self, node: ast.Call, func: ast.Attribute) -> None:
        if not node.args:
            return
        words = self._consts_of(node.args[0])
        if not words:
            return
        strict = any(w.lower() in STRICT_PAYOFF_NAMES for w in words)
        specific = any(
            ID_RE.match(w) and len(w) > 2 and not _is_universal_prefix(w) for w in words
        )
        if strict or (self.symbolish(func.value) and specific):
            self.add(node.lineno, "A", "name_startswith")

    def _compare(self, node: ast.Compare) -> None:
        operands = [node.left] + list(node.comparators)
        for op, left, right in zip(node.ops, operands, operands[1:]):
            if isinstance(op, (ast.In, ast.NotIn)):
                self._membership(node, left, right)
            elif isinstance(op, (ast.Eq, ast.NotEq)):
                self._equality(node, left, right)
                self._equality(node, right, left)

    def bindings(self) -> Dict[str, ast.AST]:
        """Literals bound to a name anywhere in the module, by terminal name."""
        if self._bindings is None:
            found: Dict[str, ast.AST] = {}
            for node in self.nodes_of(ast.Assign, ast.AnnAssign):
                if isinstance(node, ast.Assign):
                    if len(node.targets) != 1:
                        continue
                    target, value = node.targets[0], node.value
                else:
                    target, value = node.target, node.value  # type: ignore
                if value is None or _literal_elements(value) is None:
                    continue
                if isinstance(target, ast.Name):
                    found.setdefault(target.id, value)
                elif isinstance(target, ast.Attribute):
                    found.setdefault(target.attr, value)
            self._bindings = found
        return self._bindings

    def _consts_of(self, node: ast.AST) -> List[str]:
        """The string constants a comparison operand stands for, if any."""
        strs = _string_elements(node)
        if strs is not None:
            return strs
        single = _const_str(node)
        if single is not None:
            return [single]
        ident = (
            node.id
            if isinstance(node, ast.Name)
            else node.attr if isinstance(node, ast.Attribute) else None
        )
        bound = self.bindings().get(ident) if ident else None
        return (_string_elements(bound) or []) if bound is not None else []

    def _membership(self, node: ast.Compare, left: ast.AST, right: ast.AST) -> None:
        words = self._consts_of(right)
        if words and _const_str(right) is None:  # name in {"a", "b"} / NAMES
            self._decide(node, left, words, "name_in")
            return
        word = _const_str(left)
        if word:  # "x" in text / "x" in funcs
            self._decide(node, right, [word], "name_in")

    def _equality(self, node: ast.Compare, const: ast.AST, other: ast.AST) -> None:
        word = _const_str(const)
        if word and _const_str(other) is None:
            self._decide(node, other, [word], "name_eq")

    def _decide(
        self, node: ast.Compare, other: ast.AST, words: List[str], kind: str
    ) -> None:
        """Class a comparison of ``other`` against string constants ``words``."""
        if self.outputish(other):
            loose = [w for w in words if _is_success_word(w) and not _is_flag_shape(w)]
            if loose:
                self.add(node.lineno, "C", "success_compare")
            return
        strict = any(w.lower() in STRICT_PAYOFF_NAMES for w in words)
        if strict or (self.symbolish(other) and _targetish(words)):
            self.add(node.lineno, "A", kind)

    # -- searches 1 and 4: literal collections -----------------------------

    def _name_uses(self, ident: str) -> List[ast.AST]:
        if self._uses is None:
            uses: Dict[str, List[ast.AST]] = defaultdict(list)
            for node in self.nodes_of(ast.Name):
                if isinstance(node.ctx, ast.Load):  # type: ignore[attr-defined]
                    uses[node.id].append(node)  # type: ignore[attr-defined]
            for node in self.nodes_of(ast.Attribute):
                if isinstance(node.ctx, ast.Load):  # type: ignore[attr-defined]
                    uses[node.attr].append(node)  # type: ignore[attr-defined]
            self._uses = uses
        return self._uses.get(ident, [])

    def search_collections(self) -> None:
        seen: Set[int] = set()
        for literal in self.nodes_of(ast.List, ast.Tuple, ast.Set, ast.Dict):
            top = literal
            parent = self.parent(top)
            while parent is not None and _wrapper_inner(parent) is top:
                top, parent = parent, self.parent(parent)
            if id(top) in seen:
                continue
            seen.add(id(top))
            strs = _string_elements(top)
            ints = _int_elements(top)
            if strs is None and ints is None:
                continue
            if strs is not None and not self._plausible_names(top, strs):
                strs = None
            if ints is not None and max(abs(i) for i in ints) < 16:
                ints = None  # byte widths and small indices are not value guesses
            if strs is None and ints is None:
                continue
            consumers, bound_to = self._consumers(top)
            if strs is not None:
                self._name_collection(top, strs, consumers, bound_to)
            if ints is not None:
                self._int_collection(top, consumers, bound_to)

    @staticmethod
    def _plausible_names(node: ast.AST, strs: List[str]) -> bool:
        """Quick reject: only collections with a payoff or success word matter."""
        return any(
            _tokens(s) & PAYOFF_TOKENS or _is_success_word(s) or _is_flag_shape(s)
            for s in strs
        )

    def _consumers(self, node: ast.AST) -> Tuple[List[ast.AST], Optional[str]]:
        """The comparisons, loops and calls that use this literal."""
        parent = self.parent(node)
        if isinstance(parent, (ast.Assign, ast.AnnAssign)):
            targets = (
                parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            )
            target = targets[0] if len(targets) == 1 else None
            ident = (
                target.id
                if isinstance(target, ast.Name)
                else target.attr if isinstance(target, ast.Attribute) else None
            )
            if ident is None:
                return [], None
            found = (self._consumer(use) for use in self._name_uses(ident))
            return [c for c in found if c is not None], ident
        consumer = self._consumer(node)
        return ([consumer] if consumer is not None else []), None

    def _consumer(self, node: ast.AST) -> Optional[ast.AST]:
        """The comparison, loop, comprehension or call that uses ``node``."""
        child, cur = node, self.parent(node)
        while cur is not None:
            if isinstance(cur, ast.Compare):
                return cur
            if isinstance(cur, (ast.For, ast.AsyncFor)) and child is cur.iter:
                return cur
            if isinstance(cur, ast.comprehension) and child is cur.iter:
                return self.parent(cur) or cur
            if isinstance(cur, ast.Call) and child in cur.args:
                return cur
            if isinstance(cur, (ast.stmt, ast.Lambda)):
                return None
            child, cur = cur, self.parent(cur)
        return None

    def _context(self, consumer: ast.AST) -> Tuple[bool, bool]:
        """(holds symbol names, holds program output) around a consumer."""
        if isinstance(consumer, (ast.For, ast.AsyncFor)):
            region: List[ast.AST] = [consumer.target, consumer.iter]
            region.extend(consumer.body[:3])
        else:
            region = [consumer]
        symbol = output = False
        for part in region:
            for sub in ast.walk(part):
                if not isinstance(sub, (ast.Name, ast.Attribute)):
                    continue
                ident = sub.id if isinstance(sub, ast.Name) else sub.attr
                toks = _tokens(ident)
                symbol = symbol or bool(toks & SYMBOL_TOKENS)
                symbol = symbol or (
                    isinstance(sub, ast.Name)
                    and ident in self._symbol_vars.get(id(self.scope(sub)), ())
                )
                output = output or bool(toks & OUTPUT_TOKENS)
        return symbol, output

    def _name_collection(
        self,
        node: ast.AST,
        strs: List[str],
        consumers: List[ast.AST],
        bound_to: Optional[str],
    ) -> None:
        if bound_to == "__all__":
            return
        idlike = [s for s in strs if ID_RE.match(s)]
        # SHOUTING_CASE ids (``consumes=("WIN", ...)``) are step and constant
        # names inside this tool, never a name looked up in a target.
        payoffish = {
            s.lower()
            for s in idlike
            if not s.isupper()
            and (_tokens(s) & PAYOFF_TOKENS or s.lower() in STRICT_PAYOFF_NAMES)
        }
        loose = [s for s in strs if _is_success_word(s) and not _is_flag_shape(s)]
        contexts = [self._context(c) for c in consumers]
        output_use = any(out and not sym for sym, out in contexts)
        symbol_use = any(sym for sym, _ in contexts)
        phrase = any(" " in s for s in loose)
        if loose and not isinstance(node, ast.Dict) and (output_use or phrase):
            self.add(node.lineno, "C", "success_words")
            return
        if isinstance(node, ast.Dict):
            return  # a record (``to_dict``) is not a name list; see search 2
        if len(payoffish) >= 2 or (len(payoffish) == 1 and symbol_use):
            self.add(node.lineno, "A", "name_list")

    def _int_collection(
        self, node: ast.AST, consumers: List[ast.AST], bound_to: Optional[str]
    ) -> None:
        used = [c for c in consumers if self._is_candidate_use(c)]
        if not used:
            return
        if bound_to is None:
            self.add(node.lineno, "B", "int_list_use")
            return
        self.add(node.lineno, "B", "int_list")
        for consumer in used:
            self.add(consumer.lineno, "B", "int_list_use")

    @staticmethod
    def _is_candidate_use(consumer: ast.AST) -> bool:
        """Iterated, or tested for membership or equality: a candidate list."""
        if isinstance(consumer, ast.Compare):
            return any(isinstance(op, _EQUALITY_OPS) for op in consumer.ops)
        return isinstance(
            consumer,
            (ast.For, ast.AsyncFor, ast.ListComp, ast.SetComp, ast.GeneratorExp),
        )

    # -- searches 5 and 6: string constants and templates -------------------

    def _segment(self, node: ast.AST) -> List[Tuple[int, str]]:
        """Raw source of a node as (line number, text) pairs."""
        start, end = node.lineno, node.end_lineno  # type: ignore[attr-defined]
        col, end_col = node.col_offset, node.end_col_offset  # type: ignore
        out: List[Tuple[int, str]] = []
        for number in range(start, end + 1):
            raw = self.line_text(number).encode("utf-8")
            lo = col if number == start else 0
            hi = end_col if number == end else len(raw)
            out.append((number, raw[lo:hi].decode("utf-8", "replace")))
        return out

    def search_strings(self) -> None:
        for node in self.strings:
            fstring = isinstance(node, ast.JoinedStr)
            for number, text in self._segment(node):
                literal = _mask_fields(text) if fstring else text
                if _is_flag_shape(literal):
                    self.add(number, "C", "flag_shape")
                self._template(number, text)

    def _template(self, number: int, text: str) -> None:
        symbol = False
        for match in TEMPLATE_SYMBOL_RE.finditer(text):
            name = match.group("name") or match.group("attr")
            if is_universal(name) or _LIBC_BEFORE_RE.search(text[: match.start()]):
                continue
            symbol = True
            self.add(number, "A'", "template_symbol")
        if symbol or _DELIMITED_WORD_RE.fullmatch(text):
            return  # a bare "win" literal's quotes are delimiters, not code
        if TEMPLATE_NAME_RE.search(text):
            self.add(number, "A'", "template_name")


# ---------------------------------------------------------------------------
# Tree scan


def scan_source(source: str, path: str = "<memory>") -> List[Hit]:
    """Every hit in one module's source, in canonical order."""
    module = _Module(path, source)
    module.search_names()
    module.search_collections()
    module.search_strings()
    return sorted(module.hits.values(), key=_sort_key)


def _sort_key(hit: Hit) -> Tuple[str, int, str, str]:
    return (hit.path, hit.line, hit.kind, hit.cls)


def package_files(root: Path = REPO_ROOT) -> List[Path]:
    return sorted((root / PACKAGE).rglob("*.py"))


def scan_tree(root: Union[str, Path] = REPO_ROOT) -> List[Hit]:
    """Every hit under ``<root>/supwngo``, in canonical order."""
    root = Path(root)
    hits: List[Hit] = []
    for file in package_files(root):
        with tokenize.open(file) as handle:
            source = handle.read()
        hits.extend(scan_source(source, file.relative_to(root).as_posix()))
    return sorted(hits, key=_sort_key)


def counts(items: Sequence[Union[Hit, Dict[str, object]]]) -> Dict[str, int]:
    """Per-class counts and the total, for hits or baseline entries."""
    out = {cls: 0 for cls in CLASSES}
    for item in items:
        cls = item.cls if isinstance(item, Hit) else str(item["class"])
        out[cls] += 1
    out["total"] = len(items)
    return out


# ---------------------------------------------------------------------------
# Baseline


def entry_id(index: int) -> str:
    return f"W-{index:04d}"


def head_commit(root: Path = REPO_ROOT) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def build_baseline(hits: Sequence[Hit], commit: str) -> Dict[str, object]:
    ordered = sorted(hits, key=_sort_key)
    entries = [
        {
            "id": entry_id(i),
            "path": h.path,
            "line": h.line,
            "class": h.cls,
            "kind": h.kind,
            "anchor": h.anchor,
            "status": "open",
        }
        for i, h in enumerate(ordered, start=1)
    ]
    return {
        "generated_by": "python3 -I scripts/audit_target_values.py --regen",
        "note": (
            "W-0 baseline. Never regenerate after W-0 and never edit by hand "
            "except an entry's status (open -> migrated | allowed). Plan "
            "section 2."
        ),
        "scanner_version": SCANNER_VERSION,
        "generated_at_commit": commit,
        "id_scheme": "W-NNNN, sequential in (path, line, kind, class) order",
        "counts": counts(ordered),
        "entries": entries,
    }


def dump_baseline(baseline: Dict[str, object]) -> str:
    """One entry per line, so a status change is a one-line diff."""
    lines = ["{"]
    for key, value in baseline.items():
        if key != "entries":
            lines.append(f"  {json.dumps(key)}: {json.dumps(value)},")
    entries = baseline["entries"]
    assert isinstance(entries, list)
    lines.append('  "entries": [')
    for i, entry in enumerate(entries):
        comma = "," if i < len(entries) - 1 else ""
        lines.append(f"    {json.dumps(entry)}{comma}")
    lines.extend(["  ]", "}"])
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument(
        "--regen",
        action="store_true",
        help="rewrite tests/data/target_values_baseline.json (W-0 only)",
    )
    parser.add_argument("--root", default=str(REPO_ROOT), help="repository root")
    args = parser.parse_args(argv)
    root = Path(args.root)
    hits = scan_tree(root)
    if args.regen:
        baseline = build_baseline(hits, head_commit(root))
        BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_PATH.write_text(dump_baseline(baseline), encoding="utf-8")
        print(f"wrote {BASELINE_PATH}: {counts(hits)}", file=sys.stderr)
        return 0
    payload = {"counts": counts(hits), "hits": [h.as_json() for h in hits]}
    json.dump(payload, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
