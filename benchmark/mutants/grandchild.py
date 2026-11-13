"""Mutant `grandchild` (SP-01 plan 3.7): leaves a detached 60 s sleeper behind.

The parent forks a child, which calls ``setsid()`` and forks a sleeper and exits.
The sleeper redirects stdin, stdout and stderr to /dev/null (so it holds no pipe
the harness waits on), writes its PID to a readiness pipe, and sleeps 60 s. The
parent waits for that PID, prints a valid success document and exits 0.

The document carries ``sleeper_pid`` so a test can check the sleeper is gone.
Under bwrap the PID namespace removes the sleeper; under the ``none`` backend
only the harness's subreaper scan can find and kill it.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _shim as shim  # noqa: E402


def spawn_sleeper():
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        os.setsid()
        if os.fork() == 0:
            devnull = os.open(os.devnull, os.O_RDWR)
            for fd in (0, 1, 2):
                os.dup2(devnull, fd)
            os.write(write_fd, str(os.getpid()).encode())
            os.close(write_fd)
            time.sleep(60)
        os._exit(0)
    os.close(write_fd)
    pid = int(os.read(read_fd, 32))
    os.waitpid(child, 0)
    os.close(read_fd)
    return pid


def handle(call):
    sleeper = spawn_sleeper()
    if call.command == "pwn":
        doc = shim.pwn_success(["ROP_SYSTEM"])
    elif call.command == "template":
        doc = shim.template_success("ret2system", call.output)
    elif call.command == "decompile":
        doc = shim.decompile_success("main", "0x401000", "int main(void)\n{\n  return 0;\n}\n")
    else:
        doc = shim.offset_success(0, None)
    doc["sleeper_pid"] = sleeper
    return doc, 0


shim.main(handle)
