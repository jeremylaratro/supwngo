"""Process-wide environment defaults for the test suite.

Both defaults here exist because of *measured* cross-test and cross-session
corruption, not as hygiene. They are set at module import — i.e. before pytest
collects a single test module, and therefore before anything can import
``pwn`` — because both hazards are decided by the state of the process at the
moment of the very first import.

``PWNLIB_NOTERM`` -- the important one
-------------------------------------
Importing ``pwn`` runs ``pwn/toplevel.py``, whose line 21 is ``import pwnlib``
and whose line 42 (in ``pwnlib/__init__.py``) is ``from . import args``. That
cascade reaches ``pwnlib/term/text.py``, which at *module scope* builds a
``Module()`` whose ``__init__`` calls ``termcap.get('reset')`` ->
``unix_termcap.init()`` -> ``curses.setupterm()``.

``curses.setupterm()`` needs a real file descriptor for stdout. pwnlib guards
that call with ``except curses.error``, which does **not** catch the
``io.UnsupportedOperation: fileno`` raised when ``sys.stdout`` is an in-memory
stream. ``click.testing.CliRunner`` installs exactly such a stream, so any test
that is the first in its process to import ``pwn`` from inside ``CliRunner``
dies there.

The damage outlives that one test. The aborted import evicts the
partially-initialised ``pwnlib`` from ``sys.modules`` but leaves every
submodule it had already finished (``pwnlib.args``, ``pwnlib.context``,
``pwnlib.term``, ...) cached. Every later ``import pwn`` in the process then
builds a *fresh, empty* ``pwnlib`` module object, and because each submodule is
now a ``sys.modules`` cache hit, nothing rebinds them as attributes of that new
object. ``pwnlib/__init__.py`` itself binds only ``version`` and ``args``, so
``from pwnlib import *`` on line 22 of ``pwn/toplevel.py`` -- which needs all 36
names in ``__all__`` -- raises::

    AttributeError: module 'pwnlib' has no attribute 'context'

...for the rest of the process. ``supwngo/core/binary.py`` catches that broadly
and degrades to "binary has no symbols", so ``rop_chain`` abstains and targets
that need a ROP technique silently collapse to ``triage``.

Setting ``PWNLIB_NOTERM`` makes ``unix_termcap.get()`` return early, so
``init()`` -- and thus ``curses.setupterm()`` -- never runs. This is a *test
harness* default rather than a product change because the failure needs a
stdout that is not fd-backed, which only happens in-process (``CliRunner``,
Jupyter -- pwnlib already special-cases Jupyter itself).

``XDG_CACHE_HOME`` -- concurrency hygiene
-----------------------------------------
pwntools keys its ROP gadget cache by the ELF's sha256 under
``$XDG_CACHE_HOME/.pwntools-cache-<pyver>/``, writes it with
``open(f, 'w+').write(repr(data))`` (truncate in place, unlocked, non-atomic)
and reads it back with an uncaught ``eval(open(f).read())``. Two sessions
analysing the same corpus binary therefore share one file, and a reader
arriving mid-write raises out of ``ROP()``. Giving each session its own cache
root removes the sharing outright. ``setdefault`` is used so an explicitly
chosen cache root still wins.
"""

from __future__ import annotations

import os
import tempfile

# Must happen at import time: conftest is imported before test collection, and
# therefore before any test module can import `pwn`.
os.environ.setdefault("PWNLIB_NOTERM", "1")
os.environ.setdefault(
    "XDG_CACHE_HOME",
    os.path.join(tempfile.gettempdir(), f"supwngo-test-cache-{os.getpid()}"),
)
