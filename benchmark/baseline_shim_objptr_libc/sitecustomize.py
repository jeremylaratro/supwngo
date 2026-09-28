"""BASELINE shim: disable ONLY the new libc-finish route, nothing else.

Why this exists
---------------
The attributable question for the ``corpus_objptr_libc`` family is "what did the
new capability add?", and the honest way to answer it is to measure the SAME
harness twice with only that capability removed. Removing it by editing the
executor or by unregistering ``objptr_hijack`` would both answer a different
question: unregistering the executor also removes the four pre-existing shapes
(``single_read``, ``table_index``, ``menu``, ``menu_leak``), so a zero would be
attributable to "no executor at all" rather than to "no libc route".

So this shim monkeypatches exactly one function -- ``build_libc_plan``, the entry
point to the ``menu_libc`` shape -- to refuse. Everything else about the pipeline,
the registry, and the ordering is untouched, and the executor still declines with
a real reason rather than crashing.

It lives OUTSIDE the package tree on purpose: no in-tree file changes, nothing to
forget to revert, and ``orchestrator.py`` / ``executors/__init__.py`` are not
touched (they are off limits).

Usage -- ABSOLUTE PATHS, and prove it applied
---------------------------------------------
    PYTHONPATH=/srv/share/dev/supwngo/benchmark/baseline_shim_objptr_libc:/srv/share/dev/supwngo \
        python benchmark/measure_family.py benchmark/corpus_objptr_libc ...

Every ``autopwn`` subprocess the harness spawns inherits PYTHONPATH, so the shim
applies to the measurement and not just to the launcher -- but ONLY if its path is
absolute. ``measure_family.py`` runs each target with ``cwd`` set to the TARGET's
directory, so a relative PYTHONPATH entry resolves against that directory, finds
nothing, and this file is never imported. There is no error when that happens: the
"baseline" arm then re-measures the FINAL arm and agrees with it perfectly.

That is exactly what happened on the first attempt here (measured: the relative-path
baseline reported 6/6 positives SOLVED with ``technique=objptr_hijack``, identical
to FINAL), so the arm is only trustworthy with a POSITIVE CONTROL first: run one
positive through the real CLI from the target's own directory with this shim on an
absolute PYTHONPATH and confirm ``success=false`` BEFORE running the family.
"""

try:
    from supwngo.exploit.pipeline.executors import objptr_hijack_techniques as _m
except Exception:  # pragma: no cover - a non-supwngo interpreter start
    pass
else:
    _REASON = ("libc call-target resolution disabled by the BASELINE shim "
               "(benchmark/baseline_shim_objptr_libc/sitecustomize.py)")

    def _disabled(binary, sites):
        return None, _REASON

    _m.build_libc_plan = _disabled

    # ``is_applicable`` gates on the same capability, so leave it consistent:
    # without the route the executor must decline at APPLICABILITY exactly as it
    # did before the route existed, not claim applicability and then fail.
    _m.find_libc_data_slots = lambda binary: []
