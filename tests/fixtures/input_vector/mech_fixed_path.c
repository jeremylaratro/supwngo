/* Mechanism: FIXED path, no argv at all. The target opens a hardcoded
   filename in its cwd. A probe that keys on argv sensitivity CANNOT see
   this -- which is exactly why the operator option is authoritative. */
#include <stdio.h>
int main(void) {
    struct { char buf[64]; unsigned int gate; } s; FILE *f;
    s.gate = 0;
    f = fopen("input.dat", "rb");
    if (!f) { puts("ERROR: input.dat not found"); return 1; }
    fread(s.buf, 1, 256, f);
    fclose(f);
    if (s.gate == 0x5AFEF11E) puts("FLAG{fixed_path}"); else puts("nope");
    return 0;
}
