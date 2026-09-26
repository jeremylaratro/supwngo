/* File-vector fixture: payload must arrive via a file named in argv[1].
   Structurally unsolvable by a stdin-only pipeline: nothing is ever read
   from fd 0. The gate constant is absent from FALLBACK_MAGIC_VALUES. */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char buf[64]; unsigned int gate = 0; FILE *f;
    if (argc < 2) { puts("ERROR: no file argument"); return 1; }
    f = fopen(argv[1], "rb");
    if (!f) { puts("ERROR: cannot open file"); return 1; }
    fread(buf, 1, 512, f);            /* overflow: 512 into buf[64] */
    fclose(f);
    if (gate == 0x5AFEF11E) { puts("FLAG{file_vector_reached}"); }
    else puts("no");
    return 0;
}
