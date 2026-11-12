/*
 * S4a call-graph fixture: a deterministic, direct caller -> callee edge.
 *
 * `entry_main` calls `leaf_helper` exactly once with a direct `call`. The port
 * of the removed angr `Function.functions_called()` to `iter_callees` must
 * recover this edge from a real angr CFG; the capstone fallback cannot (it has
 * no function knowledge base), so a run that silently falls back produces no
 * `entry_main -> leaf_helper` edge. That difference is the RED proof.
 *
 * Built with `-no-pie -fno-stack-protector -O0` so the call is a plain direct
 * relocation angr resolves, not a PLT thunk or a PIE-relative indirect.
 */
#include <stdio.h>

/* Named, non-inlinable callee. `volatile` + the printf keep -O0 from folding
 * it away and keep the call a real direct call instruction. */
int leaf_helper(int x)
{
    volatile int y = x;
    printf("leaf:%d\n", y);
    return y + 1;
}

/* Deterministic single direct call to the callee above. */
int entry_main(int argc)
{
    return leaf_helper(argc);
}

int main(int argc, char **argv)
{
    (void)argv;
    return entry_main(argc);
}
