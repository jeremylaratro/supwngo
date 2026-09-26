/* Mechanism: the payload IS an argv token -- no file anywhere. */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    struct { char buf[64]; unsigned int gate; } s;
    s.gate = 0;
    if (argc < 2) { puts("ERROR: no argument"); return 1; }
    strcpy(s.buf, argv[1]);
    if (s.gate == 0x5AFEF11E) puts("FLAG{argv_payload}"); else puts("nope");
    return 0;
}
