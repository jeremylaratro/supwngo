#!/usr/bin/env python3
"""Passcard runner (SP-01 plan sections 3.3, 3.4, 3.6, 3.8 and 8.1 V-1, V-2, V-15).

Stages every target file by file, runs the four scored commands (``pwn``,
``template``, ``decompile``, ``offset``) once per cell under the bubblewrap
sandbox, and scores the captured runs with ``passcard_score``. It reports a
7-ELF S0 matrix and, separately, the S0-PE table (2 DECOMP + 8 ROBUST cells).

Each cell is ``<scratch>/<run>/<slug>-<command>-r<rep>`` on the host and
``/tmp/cell`` inside the sandbox, with private ``tmp``, ``home`` and ``cache``
directories. ``benchmark/truth``, ``benchmark/gen``, ``tests/htb-targets``, every
source directory, the scratch root, ``$XDG_RUNTIME_DIR`` and each
``--extra-hide`` path are hidden. The harness is a child subreaper and scans for
adopted children after every cell, so a survivor is found on either backend.

The Ghidra control cell (V-2) runs first, against the real product CLI. It is a
precondition and is excluded from every denominator: if it fails, or the pinned
SHA-256 differs, the run is INVALID and never accepted.

Exit codes: 0 report written; 2 usage or environment error; 3 the time quorum
was not met (``time_quorum_failed``); 4 the run is invalid (control or pinned
fixture SHA-256).

With ``--reps N`` the semantic and ROBUST metrics are scored on rep 1 (so the
S0 matrix keeps its pinned 28 ROBUST cells); later reps add TIME samples and are
checked for the same verdicts (``stable`` in the report).
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import importlib.metadata as _metadata
import json
import math
import os
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import yaml  # noqa: E402

import passcard_preflight as preflight  # noqa: E402
import passcard_score as score  # noqa: E402
import passcard_stage as stage  # noqa: E402

SCHEMA = "passcard-report/1"

S0_ORDER = (
    "sick_rop",
    "rocket_blaster_xxx",
    "snow_scan",
    "ancient_interface",
    "auth-or-out",
    "sabotage",
    "bon-nie-appetit",
)
S0PE_ORDER = ("pe_sym", "pe_strip")

# Truth ``metrics`` tokens -> the verdict metrics they switch on.
METRIC_TOKENS: Dict[str, Tuple[str, ...]] = {
    "method": ("METHOD-R0", "METHOD-L"),
    "template": ("TEMPLATE",),
    "off": ("OFF",),
    "decomp": ("DECOMP",),
    "robust": ("ROBUST",),
}
ALL_METRICS = frozenset(score.VERDICT_METRICS)

INSIDE = "/tmp/cell"  # the cell as the sandboxed command sees it
RAW_STDOUT_CAP = 200_000
RAW_STDERR_CAP = 8_000

# Parent environment variables a cell may inherit (everything else is dropped).
ENV_PASSTHROUGH = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "JAVA_HOME", "VIRTUAL_ENV")
ENV_PASSTHROUGH_PREFIXES = ("SUPWNGO_", "GHIDRA_")
DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"

V0_LIMITS = (
    "TEMPLATE trusts the `technique` field.",
    "OFF trusts the integer, with no RIP proof.",
    "Anchors are textual after comment stripping.",
)

EXIT_OK, EXIT_USAGE, EXIT_QUORUM, EXIT_INVALID = 0, 2, 3, 4


class HarnessError(RuntimeError):
    """A configuration or environment problem the run cannot continue past."""


class TruthError(HarnessError):
    """A truth file or its target binary is unusable."""


# --- runtime (proc and sandbox) -----------------------------------------------


def load_runtime() -> Tuple[Any, Any]:
    """Import ``supwngo.core.proc`` and ``sandbox`` from this checkout.

    ``supwngo/__init__`` pulls in pwntools and angr, which the harness does not
    need, so stub package modules are registered when the real package has not
    been imported yet.
    """
    for name, rel in (("supwngo", "supwngo"), ("supwngo.core", "supwngo/core")):
        if name not in sys.modules:
            module = types.ModuleType(name)
            module.__path__ = [str(REPO / rel)]  # type: ignore[attr-defined]
            sys.modules[name] = module
    from supwngo.core import proc, sandbox  # noqa: E402

    return proc, sandbox


# --- truth -----------------------------------------------------------------------


@dataclass
class Target:
    """One scored target: its truth plus where its bytes live."""

    truth: Dict[str, Any]
    table: str  # "s0" | "s0pe"
    source_dir: Path
    target: str  # the shipped binary, relative to the cell
    metrics: FrozenSet[str]
    sha256: str = ""
    pinned_sha256: Optional[str] = None

    @property
    def slug(self) -> str:
        return self.truth["slug"]

    @property
    def sha_ok(self) -> bool:
        return self.pinned_sha256 is None or self.sha256 == self.pinned_sha256


def _metric_set(truth: Mapping[str, Any]) -> FrozenSet[str]:
    spec = truth.get("metrics", "all")
    if spec in (None, "all"):
        return ALL_METRICS
    names: set = set()
    for token in spec if isinstance(spec, list) else [spec]:
        if token not in METRIC_TOKENS:
            raise TruthError(
                "%s: unknown metrics token %r" % (truth.get("slug"), token)
            )
        names.update(METRIC_TOKENS[token])
    return frozenset(names)


def _check_truth(truth: Any, where: str) -> Dict[str, Any]:
    if not isinstance(truth, dict):
        raise TruthError("%s is not a mapping" % where)
    missing = [
        k
        for k in ("slug", "method_accept", "distance", "decompile", "stage")
        if k not in truth
    ]
    if missing:
        raise TruthError("%s lacks %s" % (where, ", ".join(missing)))
    if not isinstance(truth["stage"], dict) or not truth["stage"].get("files"):
        raise TruthError("%s: stage.files is empty" % where)
    return truth


def build_target(
    truth: Mapping[str, Any], table: str, targets_root: Path, repo: Path = REPO
) -> Target:
    """Locate a truth file's binary (one loader for ``s0`` and ``s0pe``).

    A truth with a ``binary`` block (``path`` relative to the repo, pinned
    ``sha256``) is read in place; one without it is the realpath of
    ``<targets_root>/<slug>``. ``stage.files`` is relative to that file's directory.
    """
    truth = dict(truth)
    slug = truth["slug"]
    pinned = None
    if "binary" in truth:
        spec = truth["binary"]
        path = Path(repo) / spec["path"]
        pinned = spec.get("sha256")
    else:
        path = (Path(targets_root) / slug).resolve()
    if not path.is_file():
        raise TruthError("%s: binary not found at %s" % (slug, path))
    name = path.name
    if name not in [os.path.normpath(f) for f in truth["stage"]["files"]]:
        raise TruthError(
            "%s: %s is not in stage.files %r" % (slug, name, truth["stage"]["files"])
        )
    return Target(
        truth=truth,
        table=table,
        source_dir=path.parent,
        target=name,
        metrics=_metric_set(truth),
        sha256=stage.sha256_file(path),
        pinned_sha256=pinned,
    )


def _ordered(paths: Sequence[Path], order: Sequence[str]) -> List[Path]:
    rank = {slug: i for i, slug in enumerate(order)}
    return sorted(paths, key=lambda p: (rank.get(p.stem, len(rank)), p.stem))


def load_truths(
    truth_dir: Path,
    targets_root: Path,
    *,
    repo: Path = REPO,
    only: Sequence[str] = (),
    skip_s0pe: bool = False,
) -> List[Target]:
    """Every ``<truth_dir>/s0`` and ``<truth_dir>/s0pe`` target, in report order."""
    truth_dir = Path(truth_dir)
    targets: List[Target] = []
    for table, order in (("s0", S0_ORDER), ("s0pe", S0PE_ORDER)):
        if table == "s0pe" and skip_s0pe:
            continue
        folder = truth_dir / table
        if not folder.is_dir():
            if table == "s0":
                raise TruthError("no truth directory %s" % folder)
            continue
        for path in _ordered(sorted(folder.glob("*.yaml")), order):
            truth = _check_truth(yaml.safe_load(path.read_text()), str(path))
            if only and truth["slug"] not in only:
                continue
            targets.append(build_target(truth, table, targets_root, repo))
    slugs = [t.slug for t in targets]
    if len(set(slugs)) != len(slugs):
        raise TruthError("duplicate slugs across truth tables: %r" % slugs)
    unknown = set(only) - set(slugs)
    if unknown:
        raise TruthError("--only names no truth file: %s" % ", ".join(sorted(unknown)))
    if not targets:
        raise TruthError("no targets selected")
    return targets


# --- the Ghidra control cell (V-2) ---------------------------------------------


@dataclass
class Control:
    """The control cell's expectation, from ``expect.yaml``."""

    directory: Path
    binary: str
    sha256: str
    selector: str
    address: int
    analysis_backend: str
    rc: int
    anchors: Tuple[str, ...]

    @classmethod
    def load(cls, directory: Path) -> "Control":
        directory = Path(directory)
        try:
            expect = yaml.safe_load((directory / "expect.yaml").read_text())
            return cls(
                directory=directory,
                binary=expect["binary"],
                sha256=expect["sha256"],
                selector=expect["selector"],
                address=int(expect["address"]),
                analysis_backend=expect["analysis_backend"],
                rc=int(expect["rc"]),
                anchors=tuple(expect["anchors"]["calls"]),
            )
        except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
            raise HarnessError(
                "control fixture %s is unusable: %s" % (directory, exc)
            ) from exc


_SENTINEL = re.compile(r"\s*//\s*Decompilation failed")


def _address(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    try:
        return int(value, 0) if isinstance(value, str) else None
    except ValueError:
        return None


def evaluate_control(control: Control, run: score.Run) -> List[str]:
    """Reasons the control run fails its expectation (empty means it passed)."""
    reasons: List[str] = []
    parsed = score.parse_run(run)
    if run.state != score.EXITED:
        reasons.append("state:%s" % run.state.lower())
    elif run.rc != control.rc:
        reasons.append("rc:%s!=%s" % (run.rc, control.rc))
    reasons += [
        p for p in parsed.problems if p not in reasons and p != run.state.lower()
    ]
    doc = parsed.doc
    if doc is None:
        return reasons or ["no_document"]
    if doc.get("analysis_backend") != control.analysis_backend:
        reasons.append("analysis_backend:%s" % doc.get("analysis_backend"))
    if _address(doc.get("address")) != control.address:
        reasons.append("address:%s!=%s" % (doc.get("address"), hex(control.address)))
    code = doc.get("code") if isinstance(doc.get("code"), str) else ""
    body = score.strip_comments(code).strip()
    if not body or _SENTINEL.match(code):
        reasons.append("code_empty_or_sentinel")
    for name in control.anchors:
        if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}\s*\(", body):
            reasons.append("anchor_missing:%s" % name)
    return reasons


# --- the runner ---------------------------------------------------------------


def _contains(outer: str, inner: str) -> bool:
    return inner == outer or inner.startswith(outer.rstrip("/") + "/")


def clip(text: str, cap: int) -> str:
    return text if len(text) <= cap else text[:cap]


def default_cli() -> List[str]:
    return [sys.executable, "-m", "supwngo.cli"]


def parse_cli(text: str) -> List[str]:
    """A ``--cli`` value: a JSON list, or a shell-quoted command line."""
    text = text.strip()
    if text.startswith("["):
        value = json.loads(text)
        if (
            not isinstance(value, list)
            or not all(isinstance(v, str) for v in value)
            or not value
        ):
            raise ValueError("--cli JSON must be a non-empty list of strings")
        return value
    parts = shlex.split(text)
    if not parts:
        raise ValueError("--cli is empty")
    return parts


@dataclass
class CellRecord:
    """One executed cell, as it goes in the report."""

    name: str
    command: str
    rep: int
    run: score.Run
    isolation: str
    hide_absent: List[str]
    argv: List[str]
    signal: Optional[int] = None
    errno: Optional[int] = None
    survivor_pids: List[int] = field(default_factory=list)
    survivor_info: List[str] = field(
        default_factory=list
    )  # "pid:state:comm" of each survivor
    # bwrap's own exited init, reaped and not counted (see _reap_sandbox_init)
    sandbox_init_reaped: int = 0

    def as_dict(self) -> Dict[str, Any]:
        r = self.run
        return {
            "cell": self.name,
            "command": self.command,
            "rep": self.rep,
            "isolation": self.isolation,
            "state": r.state,
            "rc": r.rc,
            "signal": self.signal,
            "errno": self.errno,
            "wall_s": round(r.wall_s, 3),
            "load1": r.load1,
            "survivors": r.survivors,
            "survivor_info": self.survivor_info,
            "sandbox_init_reaped": self.sandbox_init_reaped,
            "argv": self.argv,
            "stdout": clip(r.stdout, RAW_STDOUT_CAP),
            "stderr": clip(r.stderr, RAW_STDERR_CAP),
        }


class Harness:
    """Stages cells, runs commands in them and collects the typed results."""

    def __init__(self, args: argparse.Namespace, proc: Any, sandbox: Any):
        self.args = args
        self.proc = proc
        self.sandbox = sandbox
        self.cli: List[str] = args.cli
        self.control_cli: List[str] = args.control_cli
        if args.backend == "auto":
            self.backend = "bwrap" if sandbox.available() else "none"
        else:
            self.backend = args.backend
        # _main resolves the real scratch root (it may be created on demand) and the
        # run dir.
        self.scratch: Path = (
            Path(args.scratch_root) if args.scratch_root else Path("/var/tmp")
        )
        self.run_dir: Path = self.scratch
        self.hide: List[str] = []
        self.records: List[CellRecord] = []
        self.subreaper = False
        self.user_base = _user_base()

    # -- environment --------------------------------------------------------

    def inside(self, cell: Path) -> str:
        """The cell's path as the command sees it (bwrap remaps it; none does not)."""
        return INSIDE if self.backend == "bwrap" else str(cell)

    def env(self, inside: str) -> Dict[str, str]:
        env = {
            "HOME": inside + "/home",
            "TMPDIR": inside + "/tmp",
            "XDG_CACHE_HOME": inside + "/cache",
            "PYTHONPATH": str(REPO),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PWNLIB_NOTERM": "1",
        }
        if self.user_base:
            env["PYTHONUSERBASE"] = self.user_base
        for key, value in self.passthrough(inside).items():
            env.setdefault(key, value)
        return env

    def passthrough(self, inside: str) -> Dict[str, str]:
        """The operator variables a cell sees, and the JAVA_TOOL_OPTIONS it is given.

        The report header records exactly this, so a run under a non-default
        ``SUPWNGO_GHIDRA_TIMEOUT`` describes itself.
        """
        seen = {
            key: value
            for key, value in os.environ.items()
            if key in ENV_PASSTHROUGH or key.startswith(ENV_PASSTHROUGH_PREFIXES)
        }
        seen.setdefault("PATH", DEFAULT_PATH)
        # A JVM takes user.home from the passwd entry, not $HOME, so Ghidra's launcher
        # would write ~/.config/ghidra under the read-only real home and the product
        # `decompile` would silently fall back to angr. Point it at the cell home. An
        # operator's own options follow ours, so their -D flags still win.
        options = ["-Duser.home=%s/home" % inside]
        if os.environ.get("JAVA_TOOL_OPTIONS"):
            options.append(os.environ["JAVA_TOOL_OPTIONS"])
        seen["JAVA_TOOL_OPTIONS"] = " ".join(options)
        return dict(sorted(seen.items()))

    def command_argv(
        self, cli: Sequence[str], command: str, target: str, inside: str, extra=()
    ):
        binary = inside + "/" + target
        argv = list(cli) + [command, binary] + list(extra)
        if command == "template":
            argv += [
                "-o",
                inside + "/tmp/exploit.py",
            ]  # template writes into cwd by default
        return argv + ["--json"]

    # -- one cell --------------------------------------------------------------

    def stage(self, name: str, source_dir: Path, files, placeholders, target: str):
        return stage.stage_cell(
            self.run_dir, name, source_dir, files, placeholders, target=target
        )

    def execute(
        self,
        cell: stage.StagedCell,
        command: str,
        rep: int,
        cli: Sequence[str],
        extra=(),
    ) -> CellRecord:
        inside = self.inside(cell.path)
        argv = self.command_argv(cli, command, cell.target, inside, extra)
        load1 = os.getloadavg()[0]
        binds = [(str(cell.path), INSIDE)] if self.backend == "bwrap" else []
        res = self.sandbox.run(
            argv,
            cwd=inside,
            binds=binds,
            hide=self.hide if self.backend == "bwrap" else [],
            net=False,
            timeout=self.args.timeout,
            env=self.env(inside),
            backend=self.backend,
        )
        init_reaped = self._reap_sandbox_init() if self.backend == "bwrap" else []
        seen = {pid: _stat_state_comm(pid) for pid in self.proc.adopted_children()}
        survivors = self.proc.reap_survivors()
        run = score.Run(
            state=res.state.name,
            rc=res.rc,
            stdout=res.stdout.decode("utf-8", "replace"),
            stderr=res.stderr.decode("utf-8", "replace"),
            survivors=len(survivors),
            wall_s=res.wall_s,
            load1=load1,
        )
        record = CellRecord(
            name=cell.path.name,
            command=command,
            rep=rep,
            run=run,
            isolation=res.isolation,
            hide_absent=list(res.hide_absent),
            argv=argv,
            signal=res.signal,
            errno=res.errno,
            survivor_pids=survivors,
            survivor_info=[
                "%d:%s:%s" % ((pid, *seen[pid]) if seen.get(pid) else (pid, "?", "?"))
                for pid in survivors
            ],
            sandbox_init_reaped=len(init_reaped),
        )
        self.records.append(record)
        return record

    def _reap_sandbox_init(self, grace_s: float = 15.0) -> List[int]:
        """Reap the exited ``bwrap`` namespace init a subreaper adopts; return PIDs.

        ``bwrap --unshare-pid`` runs an init process inside the new namespace. The
        outer ``bwrap`` (the process ``proc.run`` waits for) exits as soon as that
        init signals completion, without waiting for it, so the init is orphaned
        and, because this process is a subreaper, adopted as a zombie named
        ``bwrap`` after every cell (bubblewrap 0.6.1). The frozen
        ``proc.reap_survivors`` counts zombies, so without this step every
        bwrap cell would report one survivor and ROBUST could never pass.

        Only a *zombie* whose ``comm`` is ``bwrap`` is treated this way: it is dead,
        it holds nothing, and the PID namespace has already taken every command
        descendant with it. Everything else stays a survivor. A still-live adopted
        ``bwrap`` is given ``grace_s`` to finish exiting (it has just signalled
        completion, and while it tears the namespace down it is not yet a zombie) and
        is then left for ``reap_survivors`` to count and kill. The bound is generous
        because a 2 s window proved too short once on a loaded host (a cell ended with
        the init unreaped); the normal path returns as soon as the zombie is reaped.
        """
        reaped: List[int] = []
        deadline = time.monotonic() + grace_s
        while True:
            live = False
            for pid in self.proc.adopted_children():
                info = _stat_state_comm(pid)
                if info is None or info[1] != "bwrap":
                    continue
                if info[0] == "Z":
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
                    reaped.append(pid)
                else:
                    live = True
            if not live or time.monotonic() >= deadline:
                return reaped
            time.sleep(0.005)


def _stat_state_comm(pid: int) -> Optional[Tuple[str, str]]:
    """(state, comm) from ``/proc/<pid>/stat``; None if the process is gone.

    ``comm`` may itself contain ``)``, so the line is parsed around the last one.
    """
    try:
        data = Path("/proc/%d/stat" % pid).read_bytes().decode("ascii", "replace")
    except OSError:
        return None
    close = data.rfind(")")
    open_ = data.find("(")
    if close < 0 or open_ < 0:
        return None
    fields = data[close + 2 :].split()
    return (fields[0], data[open_ + 1 : close]) if fields else None


def _user_base() -> Optional[str]:
    try:
        import site

        return site.getuserbase()
    except Exception:  # pragma: no cover - a stripped interpreter
        return None


# --- scoring one target ---------------------------------------------------------


def filter_cells(
    result: score.TargetScore, metrics: FrozenSet[str]
) -> score.TargetScore:
    """Drop the metrics a truth file does not enable (S0-PE: DECOMP, ROBUST only)."""
    if metrics >= ALL_METRICS:
        return result
    keep = [c for c in result.cells if c.metric in metrics]
    method = {"METHOD-R0", "METHOD-L"} & metrics
    return dataclasses.replace(
        result,
        cells=keep,
        precision=result.precision if "METHOD-L" in metrics else None,
        spam=result.spam if "METHOD-L" in metrics else None,
        vuln=result.vuln if method else None,
        off_unscored_numbers=result.off_unscored_numbers if "OFF" in metrics else 0,
    )


def signature(result: score.TargetScore) -> List[Tuple[Any, ...]]:
    return [(c.metric, c.kind, c.command, c.verdict, c.reason) for c in result.cells]


def cell_dict(cell: score.Cell) -> Dict[str, Any]:
    out = dataclasses.asdict(cell)
    out["warnings"] = list(cell.warnings)
    return out


@dataclass
class TargetOutcome:
    target: Target
    scores: List[score.TargetScore]  # one per rep
    runs: Dict[int, Dict[str, score.Run]]
    preflight: preflight.Preflight

    @property
    def scored(self) -> score.TargetScore:
        return self.scores[0]

    @property
    def stable(self) -> bool:
        return all(signature(s) == signature(self.scores[0]) for s in self.scores)


def time_samples(
    outcome: TargetOutcome, load_max: float
) -> Dict[str, List[Dict[str, Any]]]:
    return {
        command: [
            score.time_sample(outcome.runs[rep][command], load_max)
            for rep in sorted(outcome.runs)
        ]
        for command in score.COMMANDS
    }


# --- the report -------------------------------------------------------------------


def sha256_text_file(path: Path) -> str:
    return stage.sha256_file(path)


def _git(*args: str) -> Optional[str]:
    try:
        res = subprocess.run(
            ["git", "-C", str(REPO), *args], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout.strip() if res.returncode == 0 else None


def _version(dist: str) -> str:
    try:
        return _metadata.version(dist)
    except _metadata.PackageNotFoundError:
        return "not installed"


def ghidra_version() -> str:
    roots: List[Path] = []
    for var in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR"):
        if os.environ.get(var):
            roots.append(Path(os.environ[var]))
    for exe in (shutil.which("analyzeHeadless"), "/opt/ghidra/support/analyzeHeadless"):
        if exe and os.path.exists(exe):
            roots.append(Path(os.path.realpath(exe)).parent.parent)
    for root in roots:
        props = root / "Ghidra" / "application.properties"
        if props.is_file():
            for line in props.read_text().splitlines():
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
    return "unknown"


def build_header(
    args: argparse.Namespace,
    harness: Harness,
    proc: Any,
    sandbox: Any,
    *,
    started: str,
    load_start: Sequence[float],
) -> Dict[str, Any]:
    core = {
        "proc.py": Path(proc.__file__),
        "sandbox.py": Path(sandbox.__file__),
    }
    dirty = _git("status", "--porcelain", "--untracked-files=no")
    return {
        "schema": SCHEMA,
        "started": started,
        "git_sha": _git("rev-parse", "HEAD") or "unknown",
        "git_dirty": bool(dirty),
        "python": platform.python_version(),
        "python_executable": sys.executable,
        "pwntools": _version("pwntools"),
        "angr": _version("angr"),
        "ghidra": ghidra_version(),
        "host_arch": platform.machine(),
        "argv": list(sys.argv),
        "cli": harness.cli,
        "control_cli": harness.control_cli,
        "isolation": {
            "requested": args.backend,
            "backend": harness.backend,
            "self_check": sandbox.self_check_report(),
            "subreaper": harness.subreaper,
        },
        "load_start": list(load_start),
        "load_end": list(os.getloadavg()),
        "load_max": _finite(args.load_max),
        "reps": args.reps,
        "timeout_s": args.timeout,
        "core_sha256": {name: stage.sha256_file(path) for name, path in core.items()},
        "core_paths": {name: str(path) for name, path in core.items()},
        "hide": harness.hide,
        # With backend none the cell path differs per cell, so the header records a
        # <cell> placeholder there.
        "env_passthrough": harness.passthrough(harness.inside(Path("<cell>"))),
        "v0_limits": list(V0_LIMITS),
    }


def _env_text(env: Dict[str, str]) -> str:
    return " ".join("`%s=%s`" % item for item in env.items()) or "none"


def _finite(value: float) -> Optional[float]:
    """JSON has no infinity: an unset ``--load-max`` is recorded as null."""
    return None if math.isinf(value) else value


def _stats(values: Sequence[float]) -> Dict[str, Any]:
    if not values:
        return {"n": 0, "median": None, "max": None}
    return {"n": len(values), "median": statistics.median(values), "max": max(values)}


def table_report(
    outcomes: Sequence[TargetOutcome], load_max: float, solve: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    scores = [o.scored for o in outcomes]
    detail: Dict[str, Any] = {}
    for o in outcomes:
        s = o.scored
        entry = {
            "table": o.target.table,
            "target": o.target.target,
            "sha256": o.target.sha256,
            "preflight": dataclasses.asdict(o.preflight),
            "cells": [cell_dict(c) for c in s.cells],
            "precision": s.precision,
            "spam": s.spam,
            "vuln": s.vuln,
            "off_unscored_numbers": s.off_unscored_numbers,
            "stable": o.stable,
            "time": time_samples(o, load_max),
        }
        if solve and o.target.slug in solve["per_target"]:
            entry["solve"] = solve["per_target"][o.target.slug]
        detail[o.target.slug] = entry
    return {
        "targets": [o.target.slug for o in outcomes],
        "summary": score.aggregate(scores),
        "detail": detail,
    }


def time_report(
    outcomes: Sequence[TargetOutcome], load_max: float, quorum: Optional[int]
) -> Dict[str, Any]:
    per_command: Dict[str, Dict[str, Any]] = {}
    shortfalls: List[Dict[str, Any]] = []
    for command in score.COMMANDS:
        walls: List[float] = []
        loads: List[float] = []
        total = 0
        for o in outcomes:
            for sample in time_samples(o, load_max)[command]:
                total += 1
                if sample["valid"]:
                    walls.append(sample["wall_s"])
                    loads.append(sample["load1"])
        per_command[command] = {
            "samples": total,
            "valid": len(walls),
            "wall_s": _stats(walls),
            "load1": _stats(loads),
        }
    if quorum:
        for o in outcomes:
            samples = time_samples(o, load_max)
            if not score.time_quorum_met(samples, quorum):
                for command in score.COMMANDS:
                    valid = sum(1 for s in samples[command] if s["valid"])
                    if valid < quorum:
                        shortfalls.append(
                            {
                                "target": o.target.slug,
                                "command": command,
                                "valid": valid,
                                "needed": quorum,
                            }
                        )
    return {
        "load_max": _finite(load_max),
        "quorum": quorum,
        "per_command": per_command,
        "quorum_met": None if not quorum else not shortfalls,
        "shortfalls": shortfalls,
    }


def load_solve_artifact(
    path: Path,
    *,
    commit: Optional[str] = None,
    command: Optional[str] = None,
    cwd_convention: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingest a HYP-9 ``solve`` artefact (``scripts/htb_rescore.py`` JSON) as a column.

    Reads ``targets[slug].reps[]`` for the per-rep technique and wall time
    (``elapsed_sec``). The commit, command line and working-directory convention
    come from the options, or from like-named keys in the file; anything left unset
    is reported as missing.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text())
        targets = data["targets"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise HarnessError("solve artefact %s is unusable: %s" % (path, exc)) from exc
    meta = {
        "commit": commit or data.get("commit"),
        "command": command or data.get("command"),
        "cwd_convention": cwd_convention or data.get("cwd_convention"),
    }
    per_target: Dict[str, Any] = {}
    for slug, entry in targets.items():
        reps = []
        for rep in entry.get("reps", []):
            wall = rep.get("elapsed_sec", rep.get("wall_s"))
            reps.append(
                {
                    "technique": rep.get("technique"),
                    "wall_s": wall,
                    "level": rep.get("level"),
                    "shell_proven": rep.get("shell_proven"),
                }
            )
        per_target[slug] = {"verdict": entry.get("verdict"), "reps": reps}
    return {
        "path": str(path),
        "sha256": stage.sha256_file(path),
        "run": data.get("run"),
        "score": data.get("score"),
        **meta,
        "missing": sorted(k for k, v in meta.items() if not v),
        "per_target": per_target,
    }


# --- markdown --------------------------------------------------------------------


def _pct(value: Optional[float]) -> str:
    return "-" if value is None else "%.2f" % value


def _cell_text(cell: Mapping[str, Any]) -> str:
    verdict = cell["verdict"]
    if verdict == score.VOID:
        return "VOID(%s)" % cell["reason"]
    return verdict


def _target_row(slug: str, entry: Mapping[str, Any]) -> List[str]:
    by_metric: Dict[str, List[Mapping[str, Any]]] = {}
    for cell in entry["cells"]:
        by_metric.setdefault(cell["metric"], []).append(cell)

    def one(metric: str) -> str:
        cells = by_metric.get(metric)
        return _cell_text(cells[0]) if cells else "n/a"

    off = by_metric.get("OFF", [])
    off_text = (
        "; ".join("%s:%s" % (c["kind"], _cell_text(c)) for c in off) if off else "n/a"
    )
    robust = by_metric.get("ROBUST", [])
    failed = [c["command"] for c in robust if c["verdict"] != score.PASS]
    robust_text = "%d/%d" % (len(robust) - len(failed), len(robust))
    if failed:
        robust_text += " (fail: %s)" % ",".join(failed)
    method_l = one("METHOD-L")
    if entry["spam"] is not None:
        method_l += " p=%s s=%s" % (_pct(entry["precision"]), entry["spam"])
    pre = entry["preflight"]
    row = [
        slug,
        one("METHOD-R0"),
        method_l,
        one("TEMPLATE"),
        off_text,
        one("DECOMP"),
        robust_text,
        "ok" if pre["ok"] else pre["code"],
    ]
    return row


def _md_table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> List[str]:
    out = [
        "| " + " | ".join(header) + " |",
        "|" + "|".join("---" for _ in header) + "|",
    ]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return out


def _metric_rows(summary: Mapping[str, Any], metrics: Sequence[str]) -> List[List[str]]:
    rows = []
    for name in metrics:
        m = summary["metrics"][name]
        c = m["counts"]
        rows.append(
            [name, str(m["n"])]
            + [str(c[v]) for v in score.VERDICTS]
            + [
                _pct(m["coverage"]),
                _pct(m["exact"]),
                _pct(m["selective"]),
                _pct(m["net"]),
            ]
        )
    return rows


METRIC_HEADER = [
    "metric",
    "n",
    *score.VERDICTS,
    "coverage",
    "exact",
    "selective",
    "net",
]


def _solve_text(entry: Optional[Mapping[str, Any]]) -> str:
    if not entry:
        return "-"
    reps = entry["reps"]
    techniques = sorted({r["technique"] for r in reps if r["technique"]})
    walls = [r["wall_s"] for r in reps if isinstance(r["wall_s"], (int, float))]
    wall = " %.0fs median" % statistics.median(walls) if walls else ""
    return "%s: %s x%d%s" % (
        entry["verdict"],
        ",".join(techniques) or "-",
        len(reps),
        wall,
    )


def render_markdown(report: Mapping[str, Any]) -> str:
    head = report["header"]
    lines: List[str] = ["# Passcard report", ""]
    if report["accepted"]:
        lines.append(
            "**ACCEPTED.** Every cell ran under `bwrap` and the control cell passed."
        )
    elif not report["valid"]:
        lines.append(
            "**INVALID RUN, NOT ACCEPTED.** " + "; ".join(report["invalid_reasons"])
        )
    else:
        lines.append(
            "**NOT ACCEPTED** (an unisolated observation or a skipped precondition): "
            + "; ".join(report["not_accepted_reasons"])
        )
    lines += ["", "## Header", ""]
    iso = head["isolation"]
    rows = [
        [
            "git sha",
            "%s%s" % (head["git_sha"], " (dirty)" if head["git_dirty"] else ""),
        ],
        ["schema", head["schema"]],
        ["started", head["started"]],
        ["python", head["python"]],
        [
            "pwntools / angr / ghidra",
            "%s / %s / %s" % (head["pwntools"], head["angr"], head["ghidra"]),
        ],
        ["host arch", head["host_arch"]],
        [
            "isolation backend",
            "%s (observed: %s)"
            % (iso["backend"], ", ".join(report["isolation_observed"])),
        ],
        ["subreaper", str(iso["subreaper"])],
        [
            "load at start / end",
            "%s / %s" % (_loads(head["load_start"]), _loads(head["load_end"])),
        ],
        ["reps / timeout", "%s / %ss" % (head["reps"], head["timeout_s"])],
        ["core/proc.py sha256", head["core_sha256"]["proc.py"]],
        ["core/sandbox.py sha256", head["core_sha256"]["sandbox.py"]],
        ["argv", "`%s`" % " ".join(head["argv"])],
        ["cli", "`%s`" % " ".join(head["cli"])],
        ["cell env passthrough", _env_text(head["env_passthrough"])],
    ]
    lines += _md_table(["field", "value"], rows)
    lines += ["", "v0 limits: " + " ".join(head["v0_limits"]), ""]

    control = report["control"]
    lines += ["## Ghidra control cell (V-2)", ""]
    if not control["ran"]:
        lines.append("Skipped (`--no-control`): the run is not accepted.")
    else:
        verdict = "PASS" if control["passed"] else "FAIL"
        lines.append(
            "%s. sha256 %s, expected %s. %s"
            % (
                verdict,
                control["sha256"],
                control["expect_sha256"],
                "; ".join(control["reasons"]),
            )
        )
    lines.append("")

    s0 = report["s0"]
    lines += ["## S0 matrix (7 ELF targets, smoke, never a gate)", ""]
    solve = report.get("solve")
    header = [
        "target",
        "METHOD-R0",
        "METHOD-L",
        "TEMPLATE",
        "OFF",
        "DECOMP",
        "ROBUST",
        "preflight",
    ]
    if solve:
        header.append("solve (HYP-9)")
    rows = []
    for slug in s0["targets"]:
        row = _target_row(slug, s0["detail"][slug])
        if solve:
            row.append(_solve_text(s0["detail"][slug].get("solve")))
        rows.append(row)
    lines += _md_table(header, rows)
    lines += ["", "### S0 metrics", ""]
    lines += _md_table(
        METRIC_HEADER, _metric_rows(s0["summary"], score.VERDICT_METRICS)
    )
    lines += _extras(s0)

    pe = report["s0pe"]
    if pe["targets"]:
        lines += ["", "## S0-PE (separate table: DECOMP and ROBUST only)", ""]
        lines += _md_table(
            ["target", "DECOMP", "ROBUST", "preflight"],
            [
                [
                    slug,
                    _row_value(pe["detail"][slug], "DECOMP"),
                    _row_value(pe["detail"][slug], "ROBUST"),
                    (
                        "ok"
                        if pe["detail"][slug]["preflight"]["ok"]
                        else pe["detail"][slug]["preflight"]["code"]
                    ),
                ]
                for slug in pe["targets"]
            ],
        )
        lines += [""]
        lines += _md_table(
            METRIC_HEADER, _metric_rows(pe["summary"], ("DECOMP", "ROBUST"))
        )

    notes = _cell_notes(report)
    if notes:
        lines += ["", "## Cell notes (non-PASS cells)", ""] + notes

    lines += ["", "## TIME", ""]
    t = report["time"]
    rows = []
    for command, stats in t["per_command"].items():
        rows.append(
            [
                command,
                "%d/%d" % (stats["valid"], stats["samples"]),
                _num(stats["wall_s"]["median"]),
                _num(stats["wall_s"]["max"]),
                _num(stats["load1"]["median"]),
            ]
        )
    lines += _md_table(
        ["command", "valid/samples", "median wall s", "max wall s", "median load1"],
        rows,
    )
    quorum = t["quorum"]
    if quorum:
        lines.append("")
        lines.append(
            "Quorum %d (load < %s): %s"
            % (
                quorum,
                t["load_max"] if t["load_max"] is not None else "unset",
                "met" if t["quorum_met"] else "NOT MET (time_quorum_failed)",
            )
        )

    if solve:
        lines += ["", "## HYP-9 solve artefact", ""]
        lines.append(
            "commit %s; command `%s`; cwd convention %s; sha256 %s"
            % (
                solve["commit"] or "UNSET",
                solve["command"] or "UNSET",
                solve["cwd_convention"] or "UNSET",
                solve["sha256"],
            )
        )
        if solve["missing"]:
            lines.append("Missing metadata: " + ", ".join(solve["missing"]) + ".")
    lines.append("")
    return "\n".join(lines)


def _loads(values: Sequence[float]) -> str:
    return " ".join("%.2f" % v for v in values)


def _num(value: Optional[float]) -> str:
    return "-" if value is None else "%.2f" % value


def _row_value(entry: Mapping[str, Any], metric: str) -> str:
    cells = [c for c in entry["cells"] if c["metric"] == metric]
    if metric == "ROBUST":
        bad = [c["command"] for c in cells if c["verdict"] != score.PASS]
        return "%d/%d%s" % (
            len(cells) - len(bad),
            len(cells),
            " (fail: %s)" % ",".join(bad) if bad else "",
        )
    return _cell_text(cells[0]) if cells else "n/a"


def _extras(table: Mapping[str, Any]) -> List[str]:
    summary = table["summary"]
    prec = summary["method_l_precision"]
    lines = [
        "",
        "METHOD-L precision macro mean: %s over %d of %d targets. METHOD-SPAM: %s."
        % (
            _pct(prec["macro_mean"]),
            prec["n_defined"],
            prec["n_targets"],
            ", ".join("%s=%s" % kv for kv in summary["method_spam"].items()),
        ),
        "VULN column: %s. off_unscored_numbers: %d."
        % (summary["vuln_column"] or "none", summary["off_unscored_numbers"]),
    ]
    voids = [v for m in summary["metrics"].values() for v in m["voids"]]
    if voids:
        lines.append(
            "VOID cells: "
            + "; ".join(
                "%s/%s: %s" % (v["target"], v["kind"], v["reason"]) for v in voids
            )
        )
    if summary["warnings"]:
        lines.append("Warnings: " + "; ".join(summary["warnings"]))
    return lines


def _cell_notes(report: Mapping[str, Any]) -> List[str]:
    notes: List[str] = []
    for key in ("s0", "s0pe"):
        for slug in report[key]["targets"]:
            entry = report[key]["detail"][slug]
            for c in entry["cells"]:
                if c["verdict"] in (score.PASS, score.ABSTAIN) or not c["reason"]:
                    continue
                where = c["command"] or c["kind"] or ""
                label = c["metric"] + ("/" + where if where else "")
                notes.append(
                    "- %s %s %s: %s" % (slug, label, c["verdict"], c["reason"])
                )
            if not entry["stable"]:
                notes.append("- %s: verdicts differ between reps (unstable)" % slug)
    return notes


# --- the run -----------------------------------------------------------------------


def _all_isolation(harness: Harness) -> List[str]:
    return sorted({r.isolation for r in harness.records})


def run_control(harness: Harness, control: Control) -> Dict[str, Any]:
    """Stage and run the control cell; always returns its record."""
    staged_sha = stage.sha256_file(control.directory / control.binary)
    out: Dict[str, Any] = {
        "ran": True,
        "passed": False,
        "reasons": [],
        "sha256": staged_sha,
        "expect_sha256": control.sha256,
        "selector": control.selector,
    }
    if staged_sha != control.sha256:
        out["reasons"] = ["sha256_mismatch"]
        return out
    cell = harness.stage(
        "control-decompile-r1", control.directory, [control.binary], [], control.binary
    )
    record = harness.execute(
        cell, "decompile", 1, harness.control_cli, extra=["-f", control.selector]
    )
    out["reasons"] = evaluate_control(control, record.run)
    out["passed"] = not out["reasons"]
    out["cell"] = record.as_dict()
    return out


def run_target(harness: Harness, target: Target) -> TargetOutcome:
    args = harness.args
    runs: Dict[int, Dict[str, score.Run]] = {}
    pre: Optional[preflight.Preflight] = None
    for rep in range(1, args.reps + 1):
        runs[rep] = {}
        for command in score.COMMANDS:
            name = "%s-%s-r%d" % (target.slug, command, rep)
            cell = harness.stage(
                name,
                target.source_dir,
                target.truth["stage"]["files"],
                target.truth["stage"].get("placeholders") or [],
                target.target,
            )
            if pre is None:
                pre = preflight.run_preflight(cell.path, cell.target)
            runs[rep][command] = harness.execute(cell, command, rep, harness.cli).run
    assert pre is not None
    scores = [
        filter_cells(
            score.score_target(
                target.truth,
                runs[rep],
                preflight_void=pre.void_reason,
                load_max=args.load_max,
                require_selected_by=args.require_selected_by,
            ),
            target.metrics,
        )
        for rep in sorted(runs)
    ]
    return TargetOutcome(target, scores, runs, pre)


def assemble(
    args: argparse.Namespace,
    harness: Harness,
    proc: Any,
    sandbox: Any,
    targets: Sequence[Target],
    control: Dict[str, Any],
    outcomes: Sequence[TargetOutcome],
    solve: Optional[Dict[str, Any]],
    *,
    started: str,
    load_start: Sequence[float],
) -> Dict[str, Any]:
    header = build_header(
        args, harness, proc, sandbox, started=started, load_start=load_start
    )
    observed = _all_isolation(harness)
    invalid: List[str] = []
    refused: List[str] = []
    if control["ran"] and not control["passed"]:
        invalid.append("control_failed: " + ", ".join(control["reasons"]))
    for t in targets:
        if not t.sha_ok:
            invalid.append("fixture_sha256_mismatch: %s" % t.slug)
    if not control["ran"]:
        refused.append("control_skipped")
    if observed != ["bwrap"]:
        refused.append("isolation:" + ",".join(observed or ["none"]))
    time = time_report(outcomes, args.load_max, args.require_time_quorum)
    if time["quorum_met"] is False:
        refused.append("time_quorum_failed")
    s0 = [o for o in outcomes if o.target.table == "s0"]
    pe = [o for o in outcomes if o.target.table == "s0pe"]
    return {
        "header": header,
        "valid": not invalid,
        "accepted": not invalid and not refused,
        "invalid_reasons": invalid,
        "not_accepted_reasons": refused,
        "isolation_observed": observed,
        "control": control,
        "s0": table_report(s0, args.load_max, solve),
        "s0pe": table_report(pe, args.load_max, solve),
        "time": time,
        "time_quorum_failed": time["quorum_met"] is False,
        "solve": solve,
        "hide_absent": sorted({p for r in harness.records for p in r.hide_absent}),
        "runs": [r.as_dict() for r in harness.records],
    }


def _hide_paths(
    args: argparse.Namespace, targets: Sequence[Target], harness: Harness
) -> List[str]:
    """The paths hidden from every command (plan 3.3): deduplicated, stably ordered."""
    paths = [
        REPO / "benchmark" / "truth",
        Path(args.truth_dir),
        REPO / "benchmark" / "gen",
        REPO / "tests" / "htb-targets",
        Path(args.targets_root),
        harness.scratch,
    ]
    paths += [t.source_dir for t in targets]
    root = Path(args.targets_root).resolve()
    if (
        root.parent.name == "htb-targets"
    ):  # the real tree, which the worktree may not hold
        paths.append(root.parent)
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        paths.append(Path(runtime))
    paths += [Path(p) for p in args.extra_hide]
    out: List[str] = []
    protected = [os.path.realpath(str(REPO)), os.path.realpath(sys.executable)]
    for path in paths:
        text = os.path.abspath(str(path))
        for keep in protected:
            if _contains(os.path.realpath(text), keep):
                raise HarnessError(
                    "hide path %s would hide the checkout or interpreter" % text
                )
        if text not in out:
            out.append(text)
    return out


def _scratch_root(requested: Optional[str]) -> Tuple[Path, bool]:
    """The scratch root and whether this run created it (and so removes it)."""
    if requested:
        path = Path(requested).resolve()
        path.mkdir(parents=True, exist_ok=True)
        stage.assert_no_dot_component(str(path), "scratch root")
        return path, False
    for base in ("/var/tmp", os.path.expanduser("~")):
        try:
            path = Path(tempfile.mkdtemp(prefix="passcard-", dir=base))
        except OSError:
            continue
        stage.assert_no_dot_component(str(path), "scratch root")
        return path, True
    raise HarnessError("no writable scratch root outside /tmp")


def _out_paths(out: str) -> Tuple[Path, Path]:
    base = Path(out)
    if base.suffix in (".json", ".md"):
        base = base.with_suffix("")
    return base.with_name(base.name + ".json"), base.with_name(base.name + ".md")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Passcard v0 runner (SP-01 plan section 3)."
    )
    p.add_argument(
        "--reps",
        type=int,
        default=1,
        help="repetitions per cell (TIME samples; default 1)",
    )
    p.add_argument(
        "--load-max",
        type=float,
        default=float("inf"),
        help=(
            "a TIME sample is valid only when the 1-minute load is strictly below "
            "this"
        ),
    )
    p.add_argument(
        "--require-time-quorum",
        type=int,
        default=None,
        metavar="N",
        help=(
            "exit 3 (time_quorum_failed) unless every (target, command) has N "
            "valid samples"
        ),
    )
    p.add_argument(
        "--cli",
        type=parse_cli,
        default=default_cli(),
        help=(
            "CLI under test: a JSON list or a quoted command line "
            "(default: this python -m supwngo.cli)"
        ),
    )
    p.add_argument(
        "--control-cli",
        type=parse_cli,
        default=None,
        help="CLI for the Ghidra control cell (default: the product CLI; test hook)",
    )
    p.add_argument(
        "--targets-root", default=str(REPO / "tests" / "htb-targets" / "organized")
    )
    p.add_argument("--truth-dir", default=str(REPO / "benchmark" / "truth"))
    p.add_argument(
        "--control-dir", default=str(REPO / "benchmark" / "fixtures" / "ghidra_control")
    )
    p.add_argument("--extra-hide", action="append", default=[], metavar="PATH")
    p.add_argument(
        "--out", default=None, help="report path prefix; writes <out>.json and <out>.md"
    )
    p.add_argument(
        "--no-control",
        action="store_true",
        help="skip the Ghidra control cell; the run is then never accepted",
    )
    p.add_argument("--backend", choices=("auto", "bwrap", "none"), default="auto")
    p.add_argument(
        "--timeout", type=float, default=600.0, help="per-command wall budget, seconds"
    )
    p.add_argument(
        "--scratch-root",
        default=None,
        help="scratch directory (default: a fresh one under /var/tmp)",
    )
    p.add_argument("--keep-scratch", action="store_true")
    p.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="SLUG",
        help="score only these targets",
    )
    p.add_argument("--skip-s0pe", action="store_true", help="omit the S0-PE table")
    p.add_argument(
        "--require-selected-by",
        action="store_true",
        help="DECOMP also requires `selected_by` (SP-01b onward)",
    )
    p.add_argument(
        "--solve-artifact",
        default=None,
        metavar="PATH",
        help="HYP-9 solve artefact (scripts/htb_rescore.py JSON) to ingest as a column",
    )
    p.add_argument("--solve-commit", default=None)
    p.add_argument("--solve-command", default=None)
    p.add_argument("--solve-cwd-convention", default=None)
    args = p.parse_args(argv)
    if args.reps < 1:
        p.error("--reps must be at least 1")
    if args.require_time_quorum is not None and args.require_time_quorum < 1:
        p.error("--require-time-quorum must be at least 1")
    if args.control_cli is None:
        args.control_cli = default_cli()
    return args


def summary_text(report: Mapping[str, Any], json_path: Path, md_path: Path) -> str:
    lines = []
    ctl = report["control"]
    if not ctl["ran"]:
        control_text = "SKIPPED (--no-control)"
    elif ctl["passed"]:
        control_text = "PASS"
    else:
        control_text = "FAIL " + ", ".join(ctl["reasons"])
    lines.append("control cell: %s" % control_text)
    lines.append("isolation observed: %s" % ", ".join(report["isolation_observed"]))
    lines.append("")
    lines += _md_table(
        METRIC_HEADER, _metric_rows(report["s0"]["summary"], score.VERDICT_METRICS)
    )
    if report["s0pe"]["targets"]:
        lines.append("")
        lines.append("S0-PE")
        lines += _md_table(
            METRIC_HEADER, _metric_rows(report["s0pe"]["summary"], ("DECOMP", "ROBUST"))
        )
    lines.append("")
    state = (
        "ACCEPTED"
        if report["accepted"]
        else ("INVALID" if not report["valid"] else "NOT ACCEPTED")
    )
    reasons = report["invalid_reasons"] + report["not_accepted_reasons"]
    lines.append("%s%s" % (state, " (%s)" % "; ".join(reasons) if reasons else ""))
    lines.append("report: %s, %s" % (json_path, md_path))
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        return _main(args)
    except HarnessError as exc:
        print("passcard: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    except (stage.StageError, stage.ElfError) as exc:
        print("passcard: staging refused: %s" % exc, file=sys.stderr)
        return EXIT_USAGE


def _main(args: argparse.Namespace) -> int:
    json_path, md_path = _out_paths(
        args.out
        or str(
            REPO
            / "benchmark"
            / "results"
            / (
                "passcard-"
                + _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            )
        )
    )
    for path in (json_path, md_path):
        if path.parent.name == "baselines" and path.exists():
            raise HarnessError(
                "%s is an immutable baseline; write the post-fix run elsewhere" % path
            )

    proc, sandbox = load_runtime()
    targets = load_truths(
        Path(args.truth_dir),
        Path(args.targets_root),
        only=args.only,
        skip_s0pe=args.skip_s0pe,
    )
    solve = (
        load_solve_artifact(
            Path(args.solve_artifact),
            commit=args.solve_commit,
            command=args.solve_command,
            cwd_convention=args.solve_cwd_convention,
        )
        if args.solve_artifact
        else None
    )
    control_spec = None if args.no_control else Control.load(Path(args.control_dir))

    harness = Harness(args, proc, sandbox)
    harness.subreaper = bool(proc.become_subreaper())
    scratch, created = _scratch_root(args.scratch_root)
    # Everything after the scratch root exists, so a refusal never leaves it behind.
    try:
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        harness.scratch = scratch
        harness.run_dir = scratch / ("run-" + stamp)
        harness.run_dir.mkdir(parents=True, exist_ok=True)
        harness.hide = _hide_paths(args, targets, harness)
        started = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        load_start = list(os.getloadavg())
        if control_spec is not None:
            print("control cell ...", flush=True)
            control = run_control(harness, control_spec)
            verdict = (
                "PASS" if control["passed"] else "FAIL " + ",".join(control["reasons"])
            )
            print("  control: %s" % verdict, flush=True)
        else:
            control = {
                "ran": False,
                "passed": False,
                "reasons": [],
                "sha256": None,
                "expect_sha256": None,
            }
        outcomes = []
        for target in targets:
            print("%s ..." % target.slug, flush=True)
            outcomes.append(run_target(harness, target))
        harness.proc.reap_survivors()
        report = assemble(
            args,
            harness,
            proc,
            sandbox,
            targets,
            control,
            outcomes,
            solve,
            started=started,
            load_start=load_start,
        )
    finally:
        if created and not args.keep_scratch:
            shutil.rmtree(scratch, ignore_errors=True)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, default=str) + "\n")
    md_path.write_text(render_markdown(report))
    print(summary_text(report, json_path, md_path))

    if report["time_quorum_failed"]:
        print("time_quorum_failed", file=sys.stderr)
        return EXIT_QUORUM
    if not report["valid"]:
        return EXIT_INVALID
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
