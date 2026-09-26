/* Mechanism: line-based TEXT file reader (fgets), not a binary blob read. */
#include <stdio.h>
int main(int argc, char **argv) {
    struct { char buf[64]; unsigned int gate; } s; FILE *f; char line[512];
    s.gate = 0;
    if (argc < 2) { puts("ERROR: no file argument"); return 1; }
    f = fopen(argv[1], "r");
    if (!f) { puts("ERROR: cannot open file"); return 1; }
    if (fgets(line, sizeof(line), f)) { int i=0; while (line[i] && line[i] != '\n') { s.buf[i] = line[i]; i++; } }
    fclose(f);
    if (s.gate == 0x5AFEF11E) puts("FLAG{line_text}"); else puts("nope");
    return 0;
}
