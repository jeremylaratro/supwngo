"""Followers for the walkthrough scorer: who actually tries to follow the guide.

Two kinds, measuring two DIFFERENT things. Keeping them separate is the whole
point; collapsing them would produce one number that means neither.

  template  Executes the walkthrough's own embedded pwntools template
            (`python3 <walkthrough>.py`). Deterministic, ~free. Measures
            TEMPLATE VALIDITY: does the artifact this walkthrough ships actually
            work against this binary? This is the "literal execution" test the
            walkthrough-families plan already demands, and it is what caught
            wave 1's real defects (a NameError on an undeclared constant at the
            reader's first command; ret2shellcode taught on an NX binary).

            It says NOTHING about whether the prose teaches anything: a reader
            who cannot read a word of it still passes by typing `python3`. So the
            template follower's verdicts are TEMPLATE_OK / TEMPLATE_BROKEN and it
            is STRUCTURALLY INCAPABLE of emitting FOLLOWABLE -- see
            score.py:target_verdict(). It must never satisfy the R5 gate.

  agent     A fresh headless `claude -p` session in a sealed sandbox holding only
            a copy of the binary, its flag.txt, and (walkthrough arm only) the
            walkthrough. Nondeterministic and expensive. Measures
            FOLLOWABILITY, which is the gate metric.

            The follower's job is to produce `exploit.py`. Everything it SAYS is
            discarded: scoring reads only that file, through the same
            independent-re-execution + behavioural-attribution path
            `run_bench.py` uses on an autopwn artifact. The follower therefore
            cannot grade itself even in principle -- it is never told the flag,
            never told the verdict, and its own claims are never parsed.

BLINDNESS: WHAT IS ENFORCED AND WHAT IS ONLY DETECTED
-----------------------------------------------------
Stated plainly, because "the follower is blind" is the assumption the entire
metric rests on and asserting it would be worthless.

ENFORCED:
  - The sandbox lives outside the repository, so no CLAUDE.md, plan, prior-round
    note or corpus source is discoverable at or above the follower's cwd.
  - `--disable-slash-commands` and `--strict-mcp-config` with an empty MCP config:
    no project skills, no MCP tools, no plugin surface.
  - The environment handed to the follower has every repo-root-bearing entry
    stripped from PYTHONPATH and every SUPWNGO_* variable removed, so
    `import supwngo` fails and the corpus root is not advertised.
  - `sanitize_walkthrough()` REWRITES the walkthrough's embedded absolute binary
    path to the sandbox copy and then FAILS CLOSED if any repository path
    survives anywhere in the text. This matters: a generated walkthrough carries
    `BINARY = '<abs path into benchmark/corpus/NN_slug/>'`, and handing that over
    verbatim would hand the follower a pointer to the target's own C source. That
    single line would have made every walkthrough-arm result meaningless.

DETECTED, NOT PREVENTED:
  - A follower with a shell can search the filesystem. Nothing short of a
    container or a user namespace prevents that, and this harness does not build
    one. Instead `blindness_audit()` scans the follower's full transcript and its
    produced artifact for repository paths and corpus source filenames, and a hit
    disqualifies the rep (`BLINDNESS_SUSPECT`) rather than crediting it. That is
    a fail-closed detection, not prevention, and the report says so.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

FOLLOWER_KINDS = ("template", "agent")

ARM_WALKTHROUGH = "walkthrough"
ARM_BARE = "bare"

# The artifact every follower is asked to produce. Fixed so scoring never has to
# guess which of several files in a sandbox was meant to be the exploit.
ARTIFACT_NAME = "exploit.py"


class FollowerError(RuntimeError):
    """The follower could not be run at all (as opposed to failing to solve).

    Raised for instrument faults only. A follower that runs and does not capture
    the flag is a measurement, not an error, and must never come through here --
    turning a genuine failure into an instrument fault would shrink the
    denominator and make the score go up.
    """


@dataclass
class FollowerOutcome:
    """What a follower produced, before any scoring happens."""

    kind: str
    arm: str
    workdir: Path
    argv: list[str]
    artifact: Path | None
    ran: bool
    elapsed_sec: float
    prompt: str = ""
    transcript_path: Path | None = None
    returncode: int | None = None
    timed_out: bool = False
    blindness_hits: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # VALIDITY IS NOT SUCCESS. A follower that ran to completion and did not
    # solve the target is VALID and is a measurement. A follower that crashed,
    # ran out of budget or hit the wall clock produced NO measurement, and the
    # difference is load-bearing in the BARE arm: an invalid bare trial that
    # were treated as "did not solve" would ENABLE a FOLLOWABLE verdict on
    # missing evidence. Invalid trials force NOT_MEASURABLE instead.
    valid: bool = True
    invalid_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "invalid_reason": self.invalid_reason,
            "kind": self.kind,
            "arm": self.arm,
            "workdir": str(self.workdir),
            "argv": [str(a) for a in self.argv],
            "artifact": str(self.artifact) if self.artifact else None,
            "artifact_present": bool(self.artifact and self.artifact.is_file()
                                     and self.artifact.stat().st_size > 0),
            "ran": self.ran,
            "elapsed_sec": round(self.elapsed_sec, 1),
            "prompt": self.prompt,
            "transcript": str(self.transcript_path) if self.transcript_path else None,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "blindness_hits": self.blindness_hits,
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
# blindness
# --------------------------------------------------------------------------- #
def forbidden_context_markers(repo_root: Path, source_name: str | None) -> list[str]:
    """Strings whose appearance proves the follower reached forbidden context.

    Deliberately narrow: each entry is something that CANNOT be inferred from
    the binary alone and can only have come from the repository. A broad list
    would produce false accusations against honest followers, which is its own
    kind of dishonest measurement.
    """
    markers = [str(repo_root), "benchmark/corpus", "reference_exploits",
               "corpus.yaml", "supwngo/exploit/walkthrough"]
    if source_name:
        markers.append(source_name)
    return markers


def blindness_audit(texts: list[str], markers: list[str]) -> list[str]:
    """Which forbidden-context markers appear. Empty list means clean."""
    blob = "\n".join(t for t in texts if t)
    return sorted({m for m in markers if m and m in blob})


_ABS_PATH_RE_TEMPLATE = r"""(?P<q>['"])(?P<path>/[^'"\n]*/{name})(?P=q)"""


def sanitize_walkthrough(text: str, staged_binary: Path, repo_root: Path) -> tuple[str, dict]:
    """Repoint a walkthrough at the sandbox copy, then prove no repo path is left.

    A generated walkthrough hardcodes the binary it was generated against:

        BINARY = '/.../benchmark/corpus/02_ret2plt_system/ret2plt_system'

    Handed to a blind follower verbatim, that one line is a signpost to the
    target's own C source, the manifest and the reference exploits -- i.e. it
    silently voids the entire walkthrough arm. Only the path constant is
    rewritten; the prose, the steps and every taught constant are untouched,
    because the artifact under test must stay the artifact a user receives.

    Fails closed: if ANY repository path survives the rewrite, raise rather than
    measure. A blindness break that is merely logged would be a blindness break.
    """
    name = re.escape(staged_binary.name)
    pattern = re.compile(_ABS_PATH_RE_TEMPLATE.format(name=name), re.X)
    replaced: list[str] = []

    def _sub(m: re.Match) -> str:
        replaced.append(m.group("path"))
        return f"{m.group('q')}{staged_binary}{m.group('q')}"

    out = pattern.sub(_sub, text)

    # Comment/header mentions of the original path are not code but ARE a
    # signpost, so they are rewritten too (plain string replacement, after the
    # quoted form, so the report can distinguish the two).
    comment_hits = 0
    for original in dict.fromkeys(replaced) or []:
        if original in out:
            comment_hits += out.count(original)
            out = out.replace(original, str(staged_binary))
    # A walkthrough generated against some other path still must not leak the
    # repo; catch any remaining absolute path under the repo root.
    root = str(repo_root)
    if root in out:
        leftover = sorted({ln.strip()[:160] for ln in out.splitlines() if root in ln})
        raise FollowerError(
            "the walkthrough still contains repository paths after sanitisation, "
            "so handing it to the follower would break blindness and void the "
            f"measurement: {leftover[:3]}"
        )
    return out, {
        "quoted_paths_rewritten": sorted(dict.fromkeys(replaced)),
        "comment_occurrences_rewritten": comment_hits,
        "rewritten": bool(replaced) or bool(comment_hits),
    }


# One rule, so the redaction is auditable at a glance: a line survives only if
# it is a comment, blank, or inside the CONSTANTS region. Everything executable
# goes. The result is the TEACHING without the answer.
#
# Why this exists (peer review finding, 24 Sep 2026): a follower handed a
# runnable template can simply run it, so the verbatim-artifact metric measures
# ARTIFACT USABILITY, not prose comprehension. Naming it honestly is most of the
# fix; this variant is the other half -- it forces the follower to reconstruct
# the exploit from the explanation. A figure from one variant is NOT comparable
# to a figure from the other, and the report records which was used.
_CONSTANTS_BEGIN = re.compile(r"^\s*#\s*-+\s*$")


def redact_to_prose(text: str) -> tuple[str, dict]:
    """Strip every executable statement, keeping comments and the constants.

    Constants are kept because they carry the walkthrough's measured facts and
    their provenance (MEASURED / DERIVED / ASSUMED), which IS the teaching. A
    redaction that also removed the offset would be testing whether the follower
    can rediscover the offset, not whether the walkthrough taught it.
    """
    kept: list[str] = []
    dropped = 0
    for line in text.splitlines():
        stripped = line.strip()
        is_comment = stripped.startswith("#") or not stripped
        # A module-level constant assignment: NAME = <literal>. Nothing else.
        is_constant = bool(re.match(r"^[A-Z][A-Z0-9_]*\s*=", line))
        if is_comment or is_constant:
            kept.append(line)
        else:
            dropped += 1
    body = "\n".join(kept)
    header = (
        "# NOTE: the executable body of this walkthrough has been removed on\n"
        "# purpose. What remains is the explanation and the measured constants.\n"
        "# Build the exploit yourself from what is taught here.\n"
    )
    return header + body + "\n", {"lines_dropped": dropped, "lines_kept": len(kept)}


WALKTHROUGH_VARIANTS = ("verbatim", "prose")


def apply_variant(text: str, variant: str) -> tuple[str, dict]:
    if variant == "verbatim":
        return text, {"variant": "verbatim"}
    if variant == "prose":
        out, info = redact_to_prose(text)
        return out, {"variant": "prose", **info}
    raise FollowerError(f"unknown walkthrough variant {variant!r}; expected one "
                        f"of {', '.join(WALKTHROUGH_VARIANTS)}")


# --------------------------------------------------------------------------- #
# session teardown
# --------------------------------------------------------------------------- #
def reap_process_group(pgid: int, grace_sec: float = 2.0) -> list[int]:
    """Kill everything in process group `pgid`. Returns what needed SIGKILL.

    Called after every follower session, before the scored secret is minted.
    The scorer's whole anti-hardcoding guarantee is that the follower works
    against a DECOY and the artifact is later scored against a secret the
    follower never saw -- which fails if anything the follower started is still
    alive in the sandbox when the new secret is staged there. A surviving
    process could simply read the new `flag.txt` and write it somewhere the
    artifact will find. Found by independent review, 24 Sep 2026.

    Takes the PGID, NOT the leader's pid, deliberately: the group outlives its
    leader, so once the CLI has exited `os.getpgid(leader_pid)` raises and the
    orphans left behind -- the only ones that matter here -- would be invisible.
    The caller reads the PGID once, while the leader is still alive.

    Not a complete guarantee: a process that double-forks and calls setsid()
    leaves this group and survives. That residual is stated in the README rather
    than papered over -- closing it needs a cgroup or a PID namespace, i.e. OS
    isolation, which this process-level harness does not have.
    """
    if pgid <= 0 or pgid == os.getpgid(0):  # never signal our own group
        return []
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return []
    deadline = time.time() + grace_sec
    while time.time() < deadline:
        try:
            os.killpg(pgid, 0)
        except (ProcessLookupError, PermissionError):
            return []
        time.sleep(0.1)
    # Still there after the grace period: these are the survivors.
    survivors: list[int] = []
    try:
        os.killpg(pgid, 0)
        survivors.append(pgid)
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    return survivors


# --------------------------------------------------------------------------- #
# environment
# --------------------------------------------------------------------------- #
def follower_env(repo_root: Path, tmpdir: Path | None = None) -> dict:
    """The environment a follower -- and its scored artifact -- sees.

    Deliberately NOT `run_bench._script_env()`, which PREPENDS the repo root to
    PYTHONPATH so an autopwn-generated script can `import supwngo`. A follower
    artifact must not be able to: `supwngo` on the path would hand a blind
    follower the entire framework, including the exploit techniques it is
    supposed to be learning from the walkthrough. Every repo-bearing PYTHONPATH
    entry and every SUPWNGO_* variable is therefore removed.

    The same environment is used for the follower session AND for scoring its
    artifact, so a disagreement between the two can never be the harness's
    fault.
    """
    env = dict(os.environ)
    root = str(repo_root)
    entries = [p for p in env.get("PYTHONPATH", "").split(os.pathsep)
               if p and root not in p]
    if entries:
        env["PYTHONPATH"] = os.pathsep.join(entries)
    else:
        env.pop("PYTHONPATH", None)
    for key in [k for k in env if k.startswith("SUPWNGO_")]:
        env.pop(key, None)
    # pwntools screams without a terminfo entry and some steps shell out to gdb.
    env.setdefault("TERM", "xterm")
    if tmpdir is not None:
        env["TMPDIR"] = str(tmpdir)
    return env


# --------------------------------------------------------------------------- #
# template follower
# --------------------------------------------------------------------------- #
class TemplateFollower:
    """Runs the walkthrough's embedded template. No bare arm exists.

    There is deliberately no `bare` arm here: a deterministic executor with no
    walkthrough has nothing to execute, so it cannot supply a necessity control.
    That absence is exactly why this follower cannot emit FOLLOWABLE -- the
    necessity test is not available to it, so neither is the verdict that depends
    on one.
    """

    kind = "template"
    arms = (ARM_WALKTHROUGH,)

    def run(self, arm: str, workdir: Path, binary: Path,
            walkthrough: Path | None) -> FollowerOutcome:
        if arm != ARM_WALKTHROUGH:
            raise FollowerError(
                "the template follower has no bare arm: with no walkthrough "
                "there is no template to execute, so it cannot supply the "
                "necessity control the walkthrough gate requires")
        if walkthrough is None or not walkthrough.is_file():
            raise FollowerError(f"no walkthrough artifact at {walkthrough}")
        # The walkthrough IS the artifact; it is scored exactly as a generated
        # exploit script is, with no special casing anywhere downstream.
        return FollowerOutcome(
            kind=self.kind, arm=arm, workdir=workdir,
            argv=[sys.executable, str(walkthrough)],
            artifact=walkthrough, ran=True, elapsed_sec=0.0,
            notes=["the walkthrough's own template is the scored artifact"],
        )


# --------------------------------------------------------------------------- #
# agent follower
# --------------------------------------------------------------------------- #
# The task, stated once, shared by BOTH arms verbatim. The only difference
# between the arms is the presence of the walkthrough paragraph -- everything
# else, including the scoring rules, is identical, so a difference in outcome
# cannot be attributed to a difference in instruction.
_TASK = """\
You are given a compiled Linux x86-64 ELF binary in the current directory.

  binary : ./{binary}

Capture its flag.

Write a working exploit to ./{artifact} in this directory. Requirements:

  - {artifact} must be a self-contained Python 3 script needing only pwntools.
    Someone else will run it fresh, from this directory, with no arguments.
  - The flag must come OUT OF THE RUNNING TARGET PROCESS. Reading flag.txt,
    grepping the binary, or printing a string you found some other way is not
    an exploit and scores zero. Only bytes the target process (or a process it
    spawned, such as a shell you obtained) writes are credited.
  - When {artifact} is re-run, this is fed to its stdin:
        cat flag.txt
        echo $((6*7))
    So if your exploit lands a shell, that stdin reads the flag the way a human
    would at the prompt. Leave the process interactive at the end if so.
  - Test {artifact} yourself before you finish.

Finish by writing the file. Do not explain your work.
"""

_WALKTHROUGH_PARAGRAPH = """\

A walkthrough for this binary is provided:

  walkthrough : ./{walkthrough}

It is a step-by-step guide to exploiting this target. Read it and follow it.
"""


@dataclass
class AgentTier:
    """The follower's capability, pinned so a number is comparable across rounds.

    A stronger follower raises BOTH arms and makes more targets UNINFORMATIVE, so
    the tier is part of the measurement, not a knob. Every field here is recorded
    in report.json and a figure produced at one tier is not comparable to a
    figure produced at another.

    The default is `sonnet` -- a competent implementer, which is the population a
    teaching artifact is written for -- and deliberately not the frontier tier: a
    frontier follower would solve the easy targets bare, maximise UNINFORMATIVE
    and measure less.
    """

    model: str = "sonnet"
    effort: str | None = None
    allowed_tools: tuple[str, ...] = ("Bash", "Read", "Write", "Edit", "Glob", "Grep")
    # Denied explicitly, not merely omitted: a follower that can reach the web
    # can look up this corpus, and a walkthrough-quality number would then be
    # partly a search-engine number.
    denied_tools: tuple[str, ...] = ("WebFetch", "WebSearch", "Task")
    budget_usd: float = 2.0
    wall_timeout_sec: float = 900.0

    def to_dict(self) -> dict:
        return {
            "model_requested": self.model,
            # Stated limitation: `sonnet` is a MUTABLE ALIAS. This harness cannot
            # resolve it to an immutable identifier, so two runs months apart may
            # have used different weights under the same label. Prompts and
            # artifacts are hashed instead (see report.json); the model is not
            # pinnable from here and the number's comparability is limited by it.
            "model_is_mutable_alias": self.model in {
                "sonnet", "opus", "haiku", "fable"},
            "effort": self.effort,
            "allowed_tools": list(self.allowed_tools),
            "denied_tools": list(self.denied_tools),
            "budget_usd": self.budget_usd,
            "wall_timeout_sec": self.wall_timeout_sec,
            "cli": _claude_version(),
        }


def _claude_version() -> str:
    exe = shutil.which("claude")
    if not exe:
        return "claude CLI not found"
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True,
                           timeout=30)
        return (p.stdout or p.stderr).strip()[:120]
    except (OSError, subprocess.SubprocessError) as e:
        return f"claude --version failed: {e}"


class AgentFollower:
    """A fresh headless `claude -p` session per arm per rep."""

    kind = "agent"
    arms = (ARM_WALKTHROUGH, ARM_BARE)

    def __init__(self, tier: AgentTier, repo_root: Path,
                 mcp_config: Path, source_name: str | None = None):
        self.tier = tier
        self.repo_root = repo_root
        self.mcp_config = mcp_config
        self.source_name = source_name

    def prompt_for(self, arm: str, binary_name: str,
                   walkthrough_name: str | None) -> str:
        text = _TASK.format(binary=binary_name, artifact=ARTIFACT_NAME)
        if arm == ARM_WALKTHROUGH:
            if not walkthrough_name:
                raise FollowerError("walkthrough arm with no walkthrough file")
            text += _WALKTHROUGH_PARAGRAPH.format(walkthrough=walkthrough_name)
        return text

    def run(self, arm: str, workdir: Path, binary: Path,
            walkthrough: Path | None) -> FollowerOutcome:
        exe = shutil.which("claude")
        if not exe:
            raise FollowerError(
                "the `claude` CLI is not installed, so the agent follower cannot "
                "run. This is an instrument fault: the run reports NOT MEASURABLE "
                "rather than scoring every walkthrough unfollowable.")
        if arm == ARM_WALKTHROUGH and (walkthrough is None or not walkthrough.is_file()):
            raise FollowerError(f"no walkthrough artifact at {walkthrough}")

        prompt = self.prompt_for(
            arm, binary.name, walkthrough.name if walkthrough else None)
        artifact = workdir / ARTIFACT_NAME
        # A stale artifact from an earlier rep would be scored as this rep's
        # work, which is the difference between measuring a follower and
        # measuring its leftovers.
        if artifact.exists():
            artifact.unlink()

        argv = [exe, "-p", "--model", self.tier.model,
                "--disable-slash-commands",
                "--strict-mcp-config", "--mcp-config", str(self.mcp_config),
                "--max-budget-usd", str(self.tier.budget_usd)]
        if self.tier.effort:
            argv += ["--effort", self.tier.effort]
        # Variadic options go LAST and the prompt travels on stdin: with
        # `--allowedTools a b c "prompt"` the prompt is swallowed into the tool
        # list and the CLI exits complaining there was no prompt.
        # stream-json + --verbose so the transcript contains TOOL EVENTS, not just
        # the assistant's prose. Independent review made the point: a blindness
        # audit over plain stdout cannot see a `Read` of a forbidden path, because
        # the tool call never appears there. The audit is still detection rather
        # than prevention, but it now scans what the follower DID and not only what
        # it said about it.
        argv += ["--output-format", "stream-json", "--verbose"]
        argv += ["--disallowedTools", *self.tier.denied_tools]
        argv += ["--allowedTools", *self.tier.allowed_tools]

        env = follower_env(self.repo_root, tmpdir=workdir / ".tmp")
        (workdir / ".tmp").mkdir(exist_ok=True)

        t0 = time.time()
        timed_out = False
        # start_new_session puts the follower and everything it spawns in one
        # process group, so the whole session can be torn down afterwards. This
        # is not tidiness: the scorer re-mints the secret flag AFTER the session
        # ends, and a process that outlived the CLI could sit in the sandbox,
        # wait for the new flag to be staged, and exfiltrate a secret the
        # follower was never supposed to see. Found by independent review.
        try:
            proc = subprocess.Popen(                     # noqa: S603
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=str(workdir), env=env,
                start_new_session=True)
        except OSError as e:
            raise FollowerError(f"could not launch the follower: {e}") from e
        # Read the PGID NOW, while the leader is alive. After it exits the group
        # is unreachable through its pid -- and orphans that outlived the leader
        # are exactly the ones that matter.
        try:
            pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, PermissionError):
            pgid = proc.pid          # start_new_session makes these equal anyway
        try:
            out_b, err_b = proc.communicate(prompt.encode(),
                                            timeout=self.tier.wall_timeout_sec)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            reap_process_group(pgid)
            out_b, err_b = proc.communicate()
            rc, timed_out = None, True
        # Unconditional: a clean exit does not mean the session left nothing
        # behind.
        survivors = reap_process_group(pgid)
        elapsed = time.time() - t0

        transcript = workdir / f"follower_{arm}_transcript.txt"
        text = (out_b + err_b).decode("utf-8", "replace")
        transcript.write_text(
            f"$ (prompt on stdin)\n{prompt}\n"
            f"$ {' '.join(argv)}\n\n{text}\n")

        artifact_text = ""
        if artifact.is_file():
            artifact_text = artifact.read_text(errors="replace")
        hits = blindness_audit(
            [text, artifact_text],
            forbidden_context_markers(self.repo_root, self.source_name))

        notes = []
        invalid_reason: str | None = None
        if timed_out:
            # Even with a file on disk: a wall-clock kill can catch the artifact
            # half-written, so nothing here is a measurement.
            invalid_reason = (
                f"the follower hit the {self.tier.wall_timeout_sec}s wall timeout, "
                f"so neither its success nor its failure is evidence")
        elif rc not in (0, None):
            # ANY nonzero exit, artifact present or not. An earlier version only
            # invalidated a nonzero exit that left NO artifact, which meant a
            # crashed or budget-exhausted session that happened to leave a partial
            # exploit.py counted as an OBSERVED FAILURE -- and in the bare arm an
            # observed failure is what ENABLES a FOLLOWABLE verdict. So a crash
            # could manufacture credit for a walkthrough. Found by independent
            # review. A partial artifact is not evidence of anything.
            invalid_reason = (
                f"the follower CLI exited {rc} (artifact "
                f"{'present' if artifact.is_file() else 'absent'}) -- an "
                f"instrument fault, not a failure to solve. A crashed or "
                f"budget-exhausted session must never read as 'did not solve it'")
        if invalid_reason:
            notes.append(invalid_reason)
        elif not artifact.is_file():
            notes.append(
                f"the follower exited cleanly without producing {ARTIFACT_NAME} "
                f"-- a genuine failure to solve, and scored as one")
        if survivors:
            # Recorded, not fatal. The processes are dead before the scored
            # secret is minted, so the exfiltration window is closed; but a
            # session that leaves processes behind is worth seeing in the report.
            notes.append(
                f"the follower left {len(survivors)} process(es) running after it "
                f"exited; they were killed BEFORE the scored flag was minted, so "
                f"none of them could have seen it")

        return FollowerOutcome(
            kind=self.kind, arm=arm, workdir=workdir,
            argv=[sys.executable, str(artifact)],
            artifact=artifact if artifact.is_file() else None,
            ran=True, elapsed_sec=elapsed, prompt=prompt,
            transcript_path=transcript, returncode=rc, timed_out=timed_out,
            blindness_hits=hits, notes=notes,
            valid=invalid_reason is None, invalid_reason=invalid_reason,
        )


def build_follower(kind: str, *, tier: AgentTier, repo_root: Path,
                   mcp_config: Path, source_name: str | None):
    if kind == "template":
        return TemplateFollower()
    if kind == "agent":
        return AgentFollower(tier=tier, repo_root=repo_root,
                             mcp_config=mcp_config, source_name=source_name)
    raise FollowerError(f"unknown follower kind {kind!r}; expected one of "
                        f"{', '.join(FOLLOWER_KINDS)}")
