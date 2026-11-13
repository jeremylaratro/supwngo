/*
 * Ghidra control-cell fixture (SP-01 plan section 8.1 V-2).
 *
 * A passcard run decompiles `ghidra_control` with Ghidra before it scores any
 * target. If that does not return this function's pseudo-C with a call to
 * `puts`, the Ghidra/Java/sandbox environment is broken and the run is invalid,
 * rather than reading as product failures.
 *
 * `ghidra_control` is deliberately non-static and is built at -O0 so it is a
 * real symbol and is not inlined into `main`.
 */
#include <stdio.h>

int ghidra_control(void)
{
    puts("ghidra control cell");
    return 0;
}

int main(void)
{
    return ghidra_control();
}
