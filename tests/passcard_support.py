"""Shared helpers for the passcard tests (not a test module).

Import with ``sys.path.insert(0, str(Path(__file__).parent))`` first, as the
benchmark modules are imported. Everything here is plain functions and constants.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARK = REPO_ROOT / "benchmark"
RUNNER = BENCHMARK / "passcard.py"
MUTANTS = BENCHMARK / "mutants"

# The S0 binaries are gitignored. PASSCARD_TARGETS_ROOT points a checkout that
# lacks them (a fresh worktree) at the ones in another checkout.
TARGETS_ROOT = Path(
    os.environ.get("PASSCARD_TARGETS_ROOT")
    or REPO_ROOT / "tests" / "htb-targets" / "organized"
)

S0_SLUGS = [
    "sick_rop",
    "rocket_blaster_xxx",
    "snow_scan",
    "ancient_interface",
    "auth-or-out",
    "sabotage",
    "bon-nie-appetit",
]

HOST_LOADER = Path("/lib64/ld-linux-x86-64.so.2")


def have_targets() -> bool:
    return all((TARGETS_ROOT / slug).exists() for slug in S0_SLUGS)


needs_targets = pytest.mark.skipif(
    not have_targets(),
    reason="S0 binaries absent (gitignored); set PASSCARD_TARGETS_ROOT to a checkout "
    "that has tests/htb-targets/organized",
)


def have_bwrap() -> bool:
    """True when ``bwrap`` can build a PID-namespace sandbox here."""
    if shutil.which("bwrap") is None:
        return False
    try:
        probe = subprocess.run(
            ["bwrap", "--ro-bind", "/", "/", "--unshare-pid", "true"],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


needs_gcc = pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc not installed")
needs_host_loader = pytest.mark.skipif(
    not HOST_LOADER.exists(), reason="no x86-64 host loader to copy"
)
needs_bwrap = pytest.mark.skipif(not have_bwrap(), reason="bwrap sandbox unavailable")


def gcc(*args: str, cwd: Path) -> None:
    result = subprocess.run(
        ["gcc", *args], cwd=str(cwd), capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        pytest.skip("gcc could not build the fixture: %s" % result.stderr[-300:])


def tiny_elf(bits: int = 64, machine: int = 62, etype: int = 2) -> bytes:
    """A header-only ELF (no program headers): parses, never runs."""
    if bits == 64:
        return struct.pack(
            "<4sBBBBB7xHHIQQQIHHHHHH",
            b"\x7fELF", 2, 1, 1, 0, 0, etype, machine, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0,
        )  # fmt: skip
    return struct.pack(
        "<4sBBBBB7xHHIIIIIHHHHHH",
        b"\x7fELF", 1, 1, 1, 0, 0, etype, machine, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0,
    )  # fmt: skip


def build_lib_tree(root: Path) -> Path:
    """A challenge directory with a relative loader and a two-level library chain.

    ``app``      PT_INTERP ./ld/ld.so, RUNPATH $ORIGIN/lib, NEEDED libfoo.so
    ``app2``     PT_INTERP ./ld/ld.so, no RUNPATH, NEEDED libbar.so (next to the loader)
    ``lib/libfoo.so``  RUNPATH $ORIGIN, NEEDED libbar.so
    plus decoys that no search path reaches (source, .debug, notes, a stray libc).
    Returns the source directory.
    """
    build, src = root / "build", root / "src"
    for directory in (build, src / "lib", src / "ld", src / "extra"):
        directory.mkdir(parents=True, exist_ok=True)
    (build / "app.c").write_text("int foo(void);\nint main(void){return foo();}\n")
    (build / "foo.c").write_text("int bar(void);\nint foo(void){return bar();}\n")
    (build / "bar.c").write_text("int bar(void){return 0;}\n")
    (build / "app2.c").write_text("int bar(void);\nint main(void){return bar();}\n")
    gcc("-shared", "-fPIC", "-Wl,-soname,libbar.so", "-o", str(src / "lib/libbar.so"),
        "bar.c", cwd=build)  # fmt: skip
    gcc("-shared", "-fPIC", "-Wl,-soname,libfoo.so", "-Wl,--enable-new-dtags",
        "-Wl,-rpath,$ORIGIN", "-Wl,-rpath-link," + str(src / "lib"),
        "-o", str(src / "lib/libfoo.so"), "foo.c", "-L" + str(src / "lib"), "-lbar",
        cwd=build)  # fmt: skip
    gcc("-o", str(src / "app"), "app.c", "-Wl,--dynamic-linker=./ld/ld.so",
        "-Wl,--enable-new-dtags", "-Wl,-rpath,$ORIGIN/lib",
        "-Wl,-rpath-link," + str(src / "lib"), "-L" + str(src / "lib"), "-lfoo",
        cwd=build)  # fmt: skip
    shutil.copy(src / "lib/libbar.so", src / "ld/libbar.so")
    gcc("-o", str(src / "app2"), "app2.c", "-Wl,--dynamic-linker=./ld/ld.so",
        "-L" + str(src / "ld"), "-lbar", cwd=build)  # fmt: skip
    shutil.copy(os.path.realpath(HOST_LOADER), src / "ld/ld.so")
    # Decoys.
    (src / "app.c").write_text("/* the answer key */\n")
    (src / "app.debug").write_bytes(b"debug sibling")
    (src / "notes.txt").write_text("write-up\n")
    shutil.copy(src / "lib/libbar.so", src / "lib/libunused.so")
    shutil.copy(src / "lib/libbar.so", src / "extra/libc.so.6")
    return src


# --- running benchmark/passcard.py ------------------------------------------------


def run_runner(
    args: Sequence[Any],
    out: Path,
    *,
    timeout: float = 600,
    env_extra: Optional[Dict[str, str]] = None,
) -> Tuple[subprocess.CompletedProcess, Optional[Dict[str, Any]]]:
    """Run the runner as a subprocess (it makes itself a subreaper, so never in-process).

    Returns the completed process and the parsed JSON report, or None when the
    run wrote none (a usage error).
    """
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(env_extra or {})
    cmd = [sys.executable, "-B", str(RUNNER), *[str(a) for a in args], "--out", str(out)]
    done = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=env, cwd=str(REPO_ROOT)
    )
    report_path = Path(str(out) + ".json")
    report = json.loads(report_path.read_text()) if report_path.exists() else None
    return done, report


def cli_arg(*argv: Any) -> str:
    """A ``--cli`` value (JSON list) that runs ``python3 <argv...>``."""
    return json.dumps([sys.executable, *[str(a) for a in argv]])


def by_cell(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """The report's per-command records keyed by cell name."""
    return {rec["cell"]: rec for rec in report["runs"]}


def verdicts(report: Dict[str, Any], table: str = "s0") -> Dict[Tuple[str, str], List[str]]:
    """``{(slug, metric): [verdict, ...]}`` from a report table (ROBUST has one per command)."""
    out: Dict[Tuple[str, str], List[str]] = {}
    for slug, entry in report[table]["detail"].items():
        for cell in entry["cells"]:
            out.setdefault((slug, cell["metric"]), []).append(cell["verdict"])
    return out


# --- S0 truth, as the mutant shims receive it -------------------------------------


def load_truth(slug: str) -> Dict[str, Any]:
    return yaml.safe_load((BENCHMARK / "truth" / "s0" / ("%s.yaml" % slug)).read_text())


def s0_binary_name(slug: str, targets_root: Optional[Path] = None) -> str:
    """The shipped file's name (``snowscan`` for ``snow_scan``): the realpath's basename."""
    return os.path.realpath((targets_root or TARGETS_ROOT) / slug).rsplit("/", 1)[-1]


def truth_bundle(slugs: Sequence[str] = tuple(S0_SLUGS)) -> Dict[str, Dict[str, Any]]:
    """The ``--truth-json`` bundle for the mutant shims, keyed by the binary's file name.

    This is the only way a shim learns the right answer: the test hands it over
    explicitly, because the sandbox hides ``benchmark/truth`` from the command.
    """
    bundle: Dict[str, Dict[str, Any]] = {}
    for slug in slugs:
        truth = load_truth(slug)
        known = {
            d["kind"]: d["value"] for d in truth["distance"] if d.get("state") == "known_value"
        }
        accept = truth["method_accept"][0]
        bundle[s0_binary_name(slug)] = {
            "approach": accept,
            "technique": accept,
            "offset": known.get("buf_to_ret"),
            "canary_offset": known.get("buf_to_canary"),
            "function": "f",
            "address": hex(truth["decompile"]["default_function_any_of"][0]),
            "calls": list(truth["decompile"]["anchors"]["calls"]),
        }
    return bundle


@dataclass
class Mirror:
    """A copy of the S0 binaries (and their loader closure) outside the real tree.

    Tests that plant answer-key files plant them here, never in the real source
    directories. ``keys[slug]`` lists the four planted-or-real key paths for a target.
    """

    root: Path
    targets_root: Path
    gen_dir: Path
    keys: Dict[str, List[str]]

    def all_keys(self) -> List[str]:
        return [path for paths in self.keys.values() for path in paths]


def build_mirror(slugs: Sequence[str] = tuple(S0_SLUGS)) -> Mirror:
    """Build the mirror under /var/tmp (the caller removes ``mirror.root``).

    Per target the keys are: its truth file, a challenge source file, a ``.debug``
    sibling of the binary, and a generator-source file under ``gen/`` (the stand-in
    for ``benchmark/gen``, passed to the runner as ``--extra-hide``).
    """
    sys.path.insert(0, str(BENCHMARK))
    import passcard_stage as stage

    root = Path(tempfile.mkdtemp(prefix="passcard-mirror-", dir="/var/tmp"))
    organized, gen_dir = root / "organized", root / "gen"
    organized.mkdir()
    gen_dir.mkdir()
    keys: Dict[str, List[str]] = {}
    for slug in slugs:
        real = Path(os.path.realpath(TARGETS_ROOT / slug))
        copy_dir = root / "src" / slug
        for rel in [real.name, *stage.compute_closure(real.parent, [real.name])]:
            (copy_dir / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(real.parent / rel, copy_dir / rel)
        source = copy_dir / ("%s.c" % real.name)
        source.write_text("/* challenge source: the answer key for %s */\n" % slug)
        debug = copy_dir / ("%s.debug" % real.name)
        debug.write_bytes(b"planted debug sibling for " + slug.encode())
        generator = gen_dir / ("%s_gen.py" % slug)
        generator.write_text("# generator source with the truth for %s\n" % slug)
        (organized / slug).symlink_to("../src/%s/%s" % (slug, real.name))
        keys[slug] = [
            str(BENCHMARK / "truth" / "s0" / ("%s.yaml" % slug)),
            str(source),
            str(debug),
            str(generator),
        ]
    return Mirror(root, organized, gen_dir, keys)


# --- a synthetic world the runner can score ---------------------------------------

# One failure document that is the legal failure envelope of all four commands
# (`offset` needs `success: false` and an `error_code`; the others need `error`).
FAILURE_DOC = "{'error': 'declined', 'success': False, 'error_code': 'declined'}"

# Declines every command with the failure envelope (rc 2).
SHIM_DECLINE = (
    "import json, sys\n"
    "print(json.dumps(%s))\n"
    "sys.exit(2)\n" % FAILURE_DOC
)

# Declines, and reports what the sandboxed command sees. `--probe PATH` (repeatable,
# before the command) asks whether PATH exists; `--list PATH` lists a directory.
SHIM_ENV_DUMP = (
    "import json, os, sys\n"
    "probes = [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--probe']\n"
    "lists = [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--list']\n"
    "def listing(path):\n"
    "    try:\n"
    "        return sorted(os.listdir(path))\n"
    "    except OSError as exc:\n"
    "        return 'error:' + str(exc.errno)\n"
    "doc = %s\n"
    "doc.update({'cwd': os.getcwd(), 'env': dict(os.environ), 'argv': sys.argv,\n"
    "            'exists': {p: os.path.exists(p) for p in probes},\n"
    "            'listing': {p: listing(p) for p in lists}})\n"
    "print(json.dumps(doc))\n"
    "sys.exit(2)\n" % FAILURE_DOC
)

# A passing Ghidra control answer for `decompile`; declines anything else.
SHIM_CONTROL_OK = (
    "import json, sys\n"
    "if 'decompile' in sys.argv:\n"
    "    code = 'void ghidra_control(void)\\n{\\n  puts(\"hi\");\\n}\\n'\n"
    "    print(json.dumps({'analysis_backend': 'ghidra', 'address': '0x401136',\n"
    "                      'name': 'ghidra_control', 'code': code}))\n"
    "    sys.exit(0)\n"
    "print(json.dumps(%s))\n"
    "sys.exit(2)\n" % FAILURE_DOC
)


@dataclass
class World:
    """One S0-shaped target (``mini_a``) built outside /tmp, so a sandbox sees the shims."""

    root: Path
    truth_dir: Path
    targets_root: Path
    bin_dir: Path
    source_dir: Path

    def shim(self, name: str) -> Path:
        return self.bin_dir / name

    def cli(self, name: str) -> str:
        return cli_arg(self.shim(name))


def mini_truth(slug: str, binary: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    truth: Dict[str, Any] = {
        "slug": slug,
        "format": "elf",
        "arch": "amd64",
        "vuln_family": "stack_bof",
        "method_accept": ["ret2win"],
        "method_basis": "reviewed",
        "solve_proven": None,
        "distance": [
            {"kind": "buf_to_ret", "state": "known_value", "value": 40, "provenance": "synthetic"}
        ],
        "decompile": {
            "vuln_function": {"addr": 0x401000, "provenance": "synthetic"},
            "default_function_any_of": [0x401000],
            "anchors": {"calls": ["puts"], "min_calls": 1},
        },
        "stage": {"files": [slug], "placeholders": []},
        "forbidden_symbols": [],
    }
    if binary:
        truth["binary"] = binary
        truth["metrics"] = ["decomp", "robust"]
        truth["method_accept"] = []
        truth["distance"] = []
    return truth


def make_world(pinned_sha: Optional[str] = None) -> World:
    """Build the world under /var/tmp; the caller removes ``world.root``.

    With ``pinned_sha`` a second target ``mini_pe`` is added to ``truth/s0pe``,
    read in place (an absolute ``binary.path``) with that pinned SHA-256.
    """
    root = Path(tempfile.mkdtemp(prefix="passcard-world-", dir="/var/tmp"))
    source_dir = root / "src" / "mini_a"
    source_dir.mkdir(parents=True)
    binary = source_dir / "mini_a"
    binary.write_bytes(tiny_elf())
    binary.chmod(0o755)
    targets_root = root / "organized"
    targets_root.mkdir()
    (targets_root / "mini_a").symlink_to("../src/mini_a/mini_a")
    truth_dir = root / "truth"
    (truth_dir / "s0").mkdir(parents=True)
    (truth_dir / "s0" / "mini_a.yaml").write_text(yaml.safe_dump(mini_truth("mini_a")))
    if pinned_sha is not None:
        pe_dir = root / "pe"
        pe_dir.mkdir()
        pe = pe_dir / "mini_pe"
        pe.write_bytes(tiny_elf())
        pe.chmod(0o755)
        (truth_dir / "s0pe").mkdir()
        spec = {"path": str(pe), "sha256": pinned_sha}
        (truth_dir / "s0pe" / "mini_pe.yaml").write_text(
            yaml.safe_dump(mini_truth("mini_pe", binary=spec))
        )
    bin_dir = root / "bin"
    bin_dir.mkdir()
    (bin_dir / "decline.py").write_text(SHIM_DECLINE)
    (bin_dir / "control_ok.py").write_text(SHIM_CONTROL_OK)
    (bin_dir / "env_dump.py").write_text(SHIM_ENV_DUMP)
    return World(root, truth_dir, targets_root, bin_dir, source_dir)
