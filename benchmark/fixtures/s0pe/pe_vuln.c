/*
 * S0-PE fixture source (SP-01 plan section 8.1 V-15, V-9).
 *
 * Built with mingw-w64 into two PE64 binaries, one with symbols (pe_sym.exe)
 * and one stripped (pe_strip.exe). The S0-PE table scores `decompile` and the
 * ROBUST commands on both; it never runs the binary.
 *
 * `pe_vuln` is the user function the decompile truth names. It is non-static
 * and the build is -O0, so it is a real function called from `main` and is not
 * inlined. The truth accepts only the user `main` as the default function
 * (plan V-9): on the stripped build the PE entry point is the CRT start, not
 * `main`, so falling back to it is an honest DECOMP FAIL.
 */
#include <stdio.h>

int pe_vuln(void)
{
    puts("pe_vuln reached");
    return 0;
}

int main(void)
{
    return pe_vuln();
}
