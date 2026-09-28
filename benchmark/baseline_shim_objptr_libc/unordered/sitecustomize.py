"""ORDERING shim: keep `objptr_hijack` REGISTERED but drop it from FIRST_TECHNIQUES.

The question this answers is narrow and is the only one it answers: does the
`menu_libc` shape need the front position `objptr_hijack` already holds, or would
it be reached in time anyway under the default StrategySuggester order? The
capability is untouched -- the executor is still registered and still builds the
same plan -- so a difference between the two arms is attributable to ORDER alone.

Same absolute-path discipline as the sibling baseline shim, and for the same
reason (see its docstring): ``measure_family.py`` and ``htb_rescore.py`` both run
each target with ``cwd`` set to the target's directory, so a relative PYTHONPATH
entry silently never resolves.

    PYTHONPATH=/srv/share/dev/supwngo/benchmark/baseline_shim_objptr_libc/unordered:/srv/share/dev/supwngo \
        python -m supwngo.cli autopwn ./auth-or-out --json --no-legacy --timeout 300

Prove it applied before trusting the arm: the attempt list must show
`objptr_hijack` well down the order rather than as attempt 5.
"""

try:
    from supwngo.exploit.pipeline import orchestrator as _o
except Exception:  # pragma: no cover - a non-supwngo interpreter start
    pass
else:
    _o.FIRST_TECHNIQUES = [t for t in _o.FIRST_TECHNIQUES if t != "objptr_hijack"]
