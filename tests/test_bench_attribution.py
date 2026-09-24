"""Regression tests for benchmark/attribution.py's process-tree reasoning.

These are fixture-driven: each builds a synthetic `strace -f -o` log and asserts
who gets credited for the flag-bearing write. Both defects covered here were
found against real exploits, and both are properties of the TRACE rather than of
the exploit -- which is why a fixture can pin them exactly.

Each test in the two defect classes fails against the pre-fix module.
"""
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTRIB = REPO_ROOT / "benchmark" / "attribution.py"


def _load_attribution():
    spec = importlib.util.spec_from_file_location("attribution_under_test", ATTRIB)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


at = _load_attribution()

FLAG = "FLAG{0123456789abcdef0123456789abcd}"


def _trace(tmp_path, lines):
    p = tmp_path / "strace.log"
    p.write_text("\n".join(lines) + "\n")
    return p


def _target(tmp_path, name):
    t = tmp_path / name
    t.write_bytes(b"\x7fELF")
    return t


class TestAttributionInPlaceExec:
    """Defect A: `execve` in place replaces a pid's image, not its lineage.

    Shellcode and SROP solves end by exec'ing a shell in the TARGET's own pid,
    so that pid is reported as `dash` and identifying the target by its current
    image finds no target at all -- a false VOID against real exploitation.
    """

    def _log(self, tmp_path):
        # 646913 python spawns 646974, which execs the TARGET and then, via the
        # exploit's shellcode, execs dash IN PLACE. dash spawns cat, which
        # writes the flag. Only 646974 ever held the target's image, and it no
        # longer does by the time anything is written.
        return _trace(tmp_path, [
            '646913 execve("/usr/bin/python3", ["python3"], 0x1) = 0',
            "646913 clone3({flags=CLONE_VM}, 88) = 646974",
            '646974 execve("./shellcode_stack", ["./shellcode_stack"], 0x1) = 0',
            '646974 execve("/usr/bin/dash", ["sh"], 0x1) = 0',
            "646974 clone3({flags=CLONE_VM}, 88) = 647098",
            '647098 execve("/usr/bin/cat", ["cat", "flag.txt"], 0x1) = 0',
            f'647098 write(1, "{FLAG}\\n", 39) = 39',
        ])

    def test_target_relabelled_by_execve_is_still_credited(self, tmp_path):
        target = _target(tmp_path, "shellcode_stack")
        tree = at.parse_trace(self._log(tmp_path), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert res["target_observed"], "the target ran; only its name changed"
        assert 646974 in res["target_pids"]
        assert 647098 in [w["pid"] for w in res["credited_writers"]]
        verdict, why = at.attribution_verdict(
            {**res, "available": True, "flag_in_output": True})
        assert verdict == "credited", why

    def test_in_place_shell_exec_counts_as_a_shell_witness(self, tmp_path):
        """An SROP/shellcode solve execs the shell in the target's OWN pid, so
        requiring the shell to be a *descendant* misses it."""
        target = _target(tmp_path, "shellcode_stack")
        tree = at.parse_trace(self._log(tmp_path), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert res["shell_proven"]
        assert 646974 in [s["pid"] for s in res["shell_exec_by_target"]]

    def test_scrape_then_exec_target_is_not_credited(self, tmp_path):
        """The hole the fix for A opens unless exec history is ORDERED.

        A script may print a scraped flag and only THEN exec the target. Same
        pid, so a plain 'was ever the target' test would credit the earlier
        write. Ordering is what keeps the in-place fix from becoming a false
        SUCCESS.
        """
        target = _target(tmp_path, "win_function")
        tree = at.parse_trace(_trace(tmp_path, [
            '646913 execve("/usr/bin/python3", ["python3"], 0x1) = 0',
            f'646913 write(1, "{FLAG}\\n", 39) = 39',
            '646913 execve("./win_function", ["./win_function"], 0x1) = 0',
        ]), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert res["target_observed"], "the target did run -- later"
        assert not res["flag_disclosed_by_target"], (
            "the write happened BEFORE the pid became the target")
        verdict, _why = at.attribution_verdict(
            {**res, "available": True, "flag_in_output": True})
        assert verdict == "not_credited"

    def test_a_forking_target_is_unaffected(self, tmp_path):
        """`system()` forks, so the target keeps its name. The regression fix
        must not disturb the case that already worked."""
        target = _target(tmp_path, "ret2plt_system")
        tree = at.parse_trace(_trace(tmp_path, [
            '100 execve("/usr/bin/python3", ["python3"], 0x1) = 0',
            "100 clone3({flags=CLONE_VM}, 88) = 200",
            '200 execve("./ret2plt_system", ["./ret2plt_system"], 0x1) = 0',
            "200 clone3({flags=CLONE_VM}, 88) = 300",
            '300 execve("/usr/bin/dash", ["sh", "-c", "cat flag.txt"], 0x1) = 0',
            "300 clone3({flags=CLONE_VM}, 88) = 400",
            '400 execve("/usr/bin/cat", ["cat"], 0x1) = 0',
            f'400 write(1, "{FLAG}\\n", 39) = 39',
        ]), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert res["flag_disclosed_by_target"]
        assert res["shell_proven"]


class TestAttributionSplitRecordsAndThreads:
    """Defect B: a split `write` hides the real writer while pwntools' relay
    thread echoes the same bytes and is blamed instead.

    Worse than A, because it is a false ACCUSATION against a genuine exploit,
    and non-deterministic: it depends on whether the kernel interleaves another
    pid's line mid-write. That non-determinism is why two runs of identical code
    disagreed minutes apart.
    """

    def _log(self, tmp_path):
        # 642765 python spawns a CLONE_THREAD relay (642811) and a real child
        # 642801 which execs the target, which forks dash, which forks cat.
        # cat's write is SPLIT by the relay thread's line landing mid-syscall,
        # and the relay thread echoes the same bytes in one complete line.
        return _trace(tmp_path, [
            '642765 execve("/usr/bin/python3", ["python3"], 0x1) = 0',
            "642765 clone3({flags=CLONE_VM|CLONE_FS|CLONE_THREAD|CLONE_SETTLS}, 88)"
            " = 642811",
            "642765 clone3({flags=CLONE_VM}, 88) = 642801",
            '642801 execve("./ret2plt_system", ["./ret2plt_system"], 0x1) = 0',
            "642801 clone3({flags=CLONE_VM}, 88) = 642803",
            '642803 execve("/usr/bin/dash", ["sh", "-c", "cat flag.txt"], 0x1) = 0',
            "642803 clone3({flags=CLONE_VM}, 88) = 642812",
            '642812 execve("/usr/bin/cat", ["cat", "flag.txt"], 0x1) = 0',
            f'642812 write(1, "{FLAG}\\n", 39 <unfinished ...>',
            f'642811 write(1, "{FLAG}\\n", 39) = 39',
            "642812 <... write resumed>)              = 39",
        ])

    def test_split_write_is_reassembled_and_credited(self, tmp_path):
        target = _target(tmp_path, "ret2plt_system")
        tree = at.parse_trace(self._log(tmp_path), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert 642812 in [w["pid"] for w in res["credited_writers"]], (
            "cat's write was split across two lines; rejoining it is what makes "
            f"the real writer visible (got {res})")
        verdict, why = at.attribution_verdict(
            {**res, "available": True, "flag_in_output": True})
        assert verdict == "credited", why

    def test_driver_relay_thread_is_not_an_independent_writer(self, tmp_path):
        """The decoy: a CLONE_THREAD child of the driver IS the driver."""
        target = _target(tmp_path, "ret2plt_system")
        tree = at.parse_trace(self._log(tmp_path), tmp_path)
        assert tree.process_identity(642811) == 642765, "thread resolves to driver"
        res = at.attribute(tree, target, FLAG)
        assert 642811 not in [w["pid"] for w in res["credited_writers"]], (
            "the harness's own relay thread must never be credited")
        # Still reported, as the driver's echo, rather than quietly dropped.
        assert 642811 in [w["pid"] for w in res["uncredited_writers"]]

    def test_a_thread_of_the_target_is_still_credited(self, tmp_path):
        """Resolving threads must not lose a target that writes from a thread."""
        target = _target(tmp_path, "win_function")
        tree = at.parse_trace(_trace(tmp_path, [
            '100 execve("/usr/bin/python3", ["python3"], 0x1) = 0',
            "100 clone3({flags=CLONE_VM}, 88) = 200",
            '200 execve("./win_function", ["./win_function"], 0x1) = 0',
            "200 clone3({flags=CLONE_VM|CLONE_THREAD}, 88) = 201",
            f'201 write(1, "{FLAG}\\n", 39) = 39',
        ]), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert res["flag_disclosed_by_target"], (
            "a thread of the target is the target")

    def test_resumed_tail_without_a_head_is_not_a_record(self, tmp_path):
        """A trace that began mid-syscall must not fabricate a writer."""
        target = _target(tmp_path, "win_function")
        tree = at.parse_trace(_trace(tmp_path, [
            '200 execve("./win_function", ["./win_function"], 0x1) = 0',
            "200 <... write resumed>)              = 39",
        ]), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert not res["flag_disclosed_by_target"]
        assert res["credited_writers"] == []


class TestAttributionStillRejectsNonExploitation:
    """The fixes must not open the channels attribution exists to close."""

    def test_pure_scrape_never_running_the_target_is_rejected(self, tmp_path):
        target = _target(tmp_path, "win_function")
        tree = at.parse_trace(_trace(tmp_path, [
            '100 execve("/usr/bin/python3", ["python3"], 0x1) = 0',
            f'100 write(1, "{FLAG}\\n", 39) = 39',
        ]), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert not res["target_observed"]
        verdict, why = at.attribution_verdict(
            {**res, "available": True, "flag_in_output": True})
        assert verdict == "not_credited"
        assert "never executed" in why

    def test_a_child_of_the_script_is_not_the_target(self, tmp_path):
        """`subprocess.run(['cat','flag.txt'])` -- a real child process, but of
        the script, not of the target."""
        target = _target(tmp_path, "win_function")
        tree = at.parse_trace(_trace(tmp_path, [
            '100 execve("/usr/bin/python3", ["python3"], 0x1) = 0',
            "100 clone3({flags=CLONE_VM}, 88) = 300",
            '300 execve("/usr/bin/cat", ["cat", "flag.txt"], 0x1) = 0',
            f'300 write(1, "{FLAG}\\n", 39) = 39',
        ]), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert not res["flag_disclosed_by_target"]
        verdict, _why = at.attribution_verdict(
            {**res, "available": True, "flag_in_output": True})
        assert verdict == "not_credited"

    def test_flag_split_across_two_writes_in_one_epoch_still_matches(self, tmp_path):
        target = _target(tmp_path, "win_function")
        half = len(FLAG) // 2
        tree = at.parse_trace(_trace(tmp_path, [
            '100 execve("/usr/bin/python3", ["python3"], 0x1) = 0',
            "100 clone3({flags=CLONE_VM}, 88) = 200",
            '200 execve("./win_function", ["./win_function"], 0x1) = 0',
            f'200 write(1, "{FLAG[:half]}", {half}) = {half}',
            f'200 write(1, "{FLAG[half:]}\\n", 20) = 20',
        ]), tmp_path)
        res = at.attribute(tree, target, FLAG)
        assert res["flag_disclosed_by_target"], (
            "a flag straddling two write() calls must still be found")
