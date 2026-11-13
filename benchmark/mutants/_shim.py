"""Plumbing shared by the passcard mutant shims (SP-01 plan section 3.7).

A shim stands in for ``python -m supwngo.cli`` on the four scored commands. The
harness runs it as ``<shim> [--truth-json JSON] [--keys-json JSON] <command>
<binary> [-o PATH] --json``. Each shim implements exactly one planted behaviour
and uses the real JSON field names, so the scorer sees what the product emits.

``--truth-json`` is how a test hands a shim the truth it is allowed to echo: a
mapping from the target's file name to a small bundle,

    {"<binary name>": {"approach": "SROP", "technique": "srop", "offset": 40,
                       "canary_offset": null, "function": "f",
                       "address": "0x40104f", "calls": ["vuln"]}}

A shim never reads ``benchmark/truth``: the sandbox hides it. Standard library
only, so a shim runs under any interpreter.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

COMMANDS = ("pwn", "template", "decompile", "offset")

# The 15 method families in plan section 2.2 order (bare family names map to themselves).
FAMILIES = (
    "ret2win", "ret2libc", "rop_syscall", "srop", "ret2dlresolve", "shellcode",
    "stack_pivot", "one_gadget", "fmt_write", "got_overwrite", "objptr_hijack",
    "heap_metadata", "fsop", "data_only", "env_hijack",
)  # fmt: skip

DECLINE_RC = 2  # the failure envelope's exit code
Handler = Callable[["Call"], Optional[Tuple[Any, int]]]


@dataclass
class Call:
    """One parsed invocation."""

    command: str
    binary: str
    output: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    truth: Dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return os.path.basename(self.binary)


def parse(argv: Optional[Sequence[str]] = None) -> Call:
    args = list(sys.argv[1:] if argv is None else argv)
    options: Dict[str, Any] = {}
    while args and args[0] in ("--truth-json", "--keys-json"):
        options[args[0][2:].replace("-", "_")] = json.loads(args[1])
        del args[:2]
    if len(args) < 2 or args[0] not in COMMANDS:
        raise SystemExit("shim: expected <%s> <binary> [-o PATH] [--json]" % "|".join(COMMANDS))
    call = Call(command=args[0], binary=args[1], options=options)
    rest = args[2:]
    for flag in ("-o", "--output"):
        if flag in rest:
            call.output = rest[rest.index(flag) + 1]
    call.truth = (options.get("truth_json") or {}).get(call.name, {})
    return call


# --- documents, with the real field names ---------------------------------------


def strategy(approach: str, confidence: float, priority: int) -> Dict[str, Any]:
    return {
        "approach": approach,
        "priority": priority,
        "description": "shim",
        "confidence": confidence,
        "requirements": [],
        "advantages": [],
        "disadvantages": [],
        "steps": [],
        "gadgets_needed": [],
        "notes": [],
    }


def pwn_success(approaches: Sequence[str], recommended: bool = True) -> Dict[str, Any]:
    """A ``pwn --json`` document; confidences strictly descend in list order."""
    items = [strategy(a, round(0.95 - 0.05 * i, 2), i + 1) for i, a in enumerate(approaches)]
    return {
        "binary_path": "shim",
        "arch": "amd64",
        "bits": 64,
        "protections_summary": "shim",
        "recommended": items[0] if (items and recommended) else None,
        "strategies": items,
        "notes": [],
        "warnings": [],
        "has_win_function": False,
        "win_function_addr": 0,
        "has_binsh": False,
        "is_static": False,
        "analysis_backend": "shim",
        "angr_budget_exceeded": False,
    }


def template_success(technique: str, output: Optional[str]) -> Dict[str, Any]:
    return {"technique": technique, "output": output or "exploit.py", "script_length": 100}


def decompile_success(
    function: str, address: str, code: str, calls: Sequence[str] = ()
) -> Dict[str, Any]:
    return {
        "function": function,
        "address": address,
        "return_type": "undefined8",
        "parameters": [],
        "calls": list(calls)[:20],
        "code": code,
        "vulnerabilities": [],
        "analysis_backend": "shim",
        "angr_budget_exceeded": False,
    }


def offset_success(offset: Optional[int], canary_offset: Optional[int]) -> Dict[str, Any]:
    return {
        "offset": offset,
        "crash_address": None,
        "method": "shim",
        "success": True,
        "error": None,
        "rbp_offset": None,
        "canary_offset": canary_offset,
        "register_values": {},
    }


def decline(command: str) -> Dict[str, Any]:
    """A well-formed failure envelope (exit it with ``DECLINE_RC``)."""
    if command == "offset":
        doc = offset_success(None, None)
        doc.update(success=False, error="declined", error_code="declined")
        return doc
    if command == "decompile":
        return {"error": "declined", "analysis_backend": "shim", "angr_budget_exceeded": False}
    return {"error": "declined"}


def code_with_calls(calls: Sequence[str], *, commented: bool = False) -> str:
    """A small function body that calls each name, or only mentions it in comments."""
    if commented:
        body = "".join("  /* %s(); */\n  // %s();\n" % (c, c) for c in calls)
    else:
        body = "".join("  %s();\n" % c for c in calls)
    return "void f(void)\n{\n%s}\n" % body


def truth_document(call: Call) -> Optional[Dict[str, Any]]:
    """The right answer for ``call`` from the explicit truth bundle (None without one)."""
    t = call.truth
    if not t:
        return None
    if call.command == "pwn":
        return pwn_success([t["approach"]])
    if call.command == "template":
        return template_success(t["technique"], call.output)
    if call.command == "decompile":
        return decompile_success(
            t.get("function", "f"), t["address"], code_with_calls(t["calls"]), t["calls"]
        )
    return offset_success(t.get("offset"), t.get("canary_offset"))


def emit(doc: Any, rc: int = 0) -> None:
    print(json.dumps(doc, indent=2))
    sys.stdout.flush()
    sys.exit(rc)


def main(handler: Handler) -> None:
    """Parse argv, call ``handler``, print its document and exit with its code.

    ``handler`` returns ``(document, rc)``; ``None`` means "decline" (rc 2).
    """
    call = parse()
    result = handler(call)
    if result is None:
        emit(decline(call.command), DECLINE_RC)
    doc, rc = result
    emit(doc, rc)
