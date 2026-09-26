/* Mechanism: file named by a FLAG (-f FILE), not by bare argv[1]. */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    struct { char buf[64]; unsigned int gate; } s; FILE *f; int i; const char *p = 0;
    s.gate = 0;
    for (i = 1; i + 1 < argc; i++) if (!strcmp(argv[i], "-f")) p = argv[i+1];
    if (!p) { puts("usage: prog -f FILE"); return 1; }
    f = fopen(p, "rb");
    if (!f) { puts("ERROR: cannot open file"); return 1; }
    fread(s.buf, 1, 256, f);
    fclose(f);
    if (s.gate == 0x5AFEF11E) puts("FLAG{flag_style}"); else puts("nope");
    return 0;
}
