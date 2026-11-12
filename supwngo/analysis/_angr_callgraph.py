"""angr-9.2-safe call-graph helpers for the analysis modules.

angr 9.2.213 removed ``Function.functions_called()`` (it raises
``AttributeError``). Every caller of it in this package sits inside a broad
``except`` that previously *swallowed* that error, so ``cfg``, ``static`` and
``decompile`` silently fell back to a call-graph with no angr callees at all
(uniform silent degradation -- see the S4 plan and claude-mem #65703).

``iter_callees`` is the supported-API replacement. It takes an angr
``Function`` and the functions knowledge base those functions belong to, and
yields the callee ``Function`` objects, matching the old method's semantics:

* resolve each call site's target with ``get_call_target`` (unresolved /
  indirect targets return ``None`` and are skipped);
* yield the ``Function`` for every resolved target that is *present in the
  provided kb* -- library/PLT functions included, exactly as the old method
  returned them;
* de-duplicate by target address, so a function called from several sites
  appears once (the old method returned a unique-callee set).

The helper is deliberately angr-free: it duck-types the objects it is handed,
so it is unit-testable against real angr objects without importing angr here.
"""

from typing import Iterator


def iter_callees(func, functions_kb) -> Iterator:
    """Yield unique callee ``Function`` objects of ``func``.

    Args:
        func: an angr ``Function`` exposing ``get_call_sites()`` and
            ``get_call_target(site_addr)``.
        functions_kb: the angr ``FunctionManager`` (e.g. ``cfg.kb.functions``)
            the callees should be resolved against; must support ``.get(addr)``
            returning a ``Function`` or ``None``.

    Yields:
        Callee ``Function`` objects, de-duplicated by target address, in
        call-site order.
    """
    seen = set()
    for site in func.get_call_sites():
        target = func.get_call_target(site)
        if target is None or target in seen:
            continue
        seen.add(target)
        callee = functions_kb.get(target)
        if callee is not None:
            yield callee
