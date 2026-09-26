/* Mechanism: raw open()/read() on argv[1] -- no stdio, no FILE*. */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    struct { char buf[64]; unsigned int gate; } s; int fd;
    s.gate = 0;
    if (argc < 2) { puts("ERROR: no file argument"); return 1; }
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) { puts("ERROR: cannot open file"); return 1; }
    read(fd, s.buf, 256);
    close(fd);
    if (s.gate == 0x5AFEF11E) puts("FLAG{open_read_argv}"); else puts("nope");
    return 0;
}
