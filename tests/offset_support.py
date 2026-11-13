"""Fixtures and helpers for the ``offset`` tests (not a test module).

Import with ``sys.path.insert(0, str(Path(__file__).parent))`` first.

``CRASH_ASM`` is a stack-smashing target written in assembly so that the
distance from the start of its buffer to the saved return address does not
depend on any compiler's frame layout: a 64-byte buffer, saved ``rbp``, then the
return address, so the answer is ``CRASH_OFFSET`` (72) by construction.
"""

from __future__ import annotations

import os
import resource
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional

import pytest

from passcard_support import HOST_LOADER, gcc

from supwngo.exploit import offset_finder

needs_gdb = pytest.mark.skipif(shutil.which("gdb") is None, reason="gdb not installed")

# 0x40 bytes of buffer + 8 bytes of saved rbp.
CRASH_OFFSET = 72

CRASH_ASM = """\
        .globl _start
        .text
_start:
        call    vuln
        mov     $60, %eax
        xor     %edi, %edi
        syscall
vuln:
        push    %rbp
        mov     %rsp, %rbp
        sub     $0x40, %rsp
        xor     %eax, %eax
        xor     %edi, %edi
        lea     -0x40(%rbp), %rsi
        mov     $1024, %edx
        syscall
        leave
        ret
        .section .note.GNU-stack,"",@progbits
"""

# Forks a session leader that outlives its parent and closes its stdio, as a
# daemon does. argv[1] (a token) stays in the grandchild's command line, so a
# test can find it. The 60 s sleep is a safety net, not part of any assertion.
FORK_SLEEPER_C = """\
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (fork() == 0) {
        setsid();
        int null = open("/dev/null", O_RDWR);
        dup2(null, 0);
        dup2(null, 1);
        dup2(null, 2);
        sleep(60);
        _exit(0);
    }
    return 0;
}
"""

# Never exits: after its input ends, read() returns 0 and it spins.
EOF_SPIN_C = """\
#include <unistd.h>

int main(void) {
    char buf[64];
    for (;;) {
        (void)!read(0, buf, sizeof buf);
    }
}
"""

# argv[1]: a path to try to open; argv[2]: where to record "opened" or "denied".
PROBE_C = """\
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    const char *verdict = open(argv[1], O_RDONLY) >= 0 ? "opened" : "denied";
    int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) return 3;
    (void)!write(out, verdict, strlen(verdict));
    close(out);
    return 0;
}
"""


def build_asm_crash(
    directory: Path, name: str = "crash", interp: Optional[str] = None
) -> Path:
    """Build ``CRASH_ASM`` in ``directory``; static unless ``interp`` is given.

    With ``interp`` the binary is dynamic (a ``PT_INTERP`` naming that path,
    recorded exactly as given) and links libc so that the interpreter is real.
    """
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / (name + ".s")
    source.write_text(CRASH_ASM)
    out = directory / name
    if interp is None:
        gcc("-nostdlib", "-static", "-o", str(out), str(source), cwd=directory)
    else:
        gcc(
            "-nostdlib",
            "-no-pie",
            "-o",
            str(out),
            str(source),
            "-Wl,--dynamic-linker=" + interp,
            "-Wl,--no-as-needed",
            "-lc",
            cwd=directory,
        )
    source.unlink()
    return out


def build_c(directory: Path, name: str, source: str) -> Path:
    """Compile a C ``source`` into ``directory/name``."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + ".c")
    path.write_text(source)
    out = directory / name
    gcc("-O0", "-o", str(out), str(path), cwd=directory)
    path.unlink()
    return out


def copy_host_loader(destination: Path) -> Path:
    """Copy the host's dynamic loader to ``destination`` (a regular file)."""
    if not HOST_LOADER.exists():
        pytest.skip("no x86-64 host loader to copy")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(os.path.realpath(HOST_LOADER), destination)
    destination.chmod(0o755)
    return destination


def pids_with(token: str) -> List[int]:
    """Host PIDs whose command line contains ``token``."""
    needle = token.encode()
    found = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            cmdline = Path("/proc/%s/cmdline" % name).read_bytes()
        except OSError:
            continue
        if needle in cmdline:
            found.append(int(name))
    return found


def wait_until(predicate, seconds: float = 15.0) -> bool:
    deadline = time.monotonic() + seconds
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.05)
    return bool(predicate())


def kill_all(token: str) -> None:
    for pid in pids_with(token):
        try:
            os.kill(pid, 9)
        except OSError:
            pass


def make_core(binary: Path, workdir: Path, payload: bytes) -> Optional[Path]:
    """Crash ``binary`` on ``payload`` with cores enabled; return the core file.

    The core appears in ``workdir`` as ``core.<pid>`` (the host's ``core_pattern``
    is ``core`` with ``core_uses_pid``) and is renamed ``core``. Returns ``None``
    when this host writes no core, so a caller can skip.
    """
    workdir.mkdir(parents=True, exist_ok=True)

    def enable_cores() -> None:
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (hard, hard))

    subprocess.run(
        [str(binary)],
        input=payload,
        cwd=str(workdir),
        capture_output=True,
        timeout=30,
        preexec_fn=enable_cores,
    )
    cores = sorted(workdir.glob("core*"))
    if not cores:
        return None
    stale = workdir / "core"
    cores[0].rename(stale)
    return stale


def fast_budgets(monkeypatch, binary, seconds=2.0):
    """Shorten every per-run budget of a finder on ``binary``.

    The fix has module-level budgets. The base hard-codes its timeouts in
    ``subprocess.run`` calls, so those whose ``argv[0]`` is the target or gdb
    (but not ``gdb --version``) are clamped instead, to keep a base run short.
    """
    for name in ("GDB_TIMEOUT_S", "CORE_TIMEOUT_S", "PROBE_TIMEOUT_S"):
        monkeypatch.setattr(offset_finder, name, seconds, raising=False)
    real_run = subprocess.run

    def clamped(argv, *args, **kwargs):
        runs_target = argv[0] == str(binary) or (
            argv[0] == "gdb" and argv[1:2] != ["--version"]
        )
        if runs_target:
            kwargs["timeout"] = min(kwargs.get("timeout") or seconds, seconds)
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", clamped)
