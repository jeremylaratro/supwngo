/*
 * Round-2 Target 12: format-string arbitrary write escalated to a full
 * GOT entry overwrite (multiple %hn writes covering all 8 bytes of a PLT
 * target's GOT slot), redirecting a subsequent, already-present call in
 * the program's own normal control flow into win().
 *
 * Protections: canary=OFF, NX=ON, PIE=OFF, RELRO=partial (GOT must stay
 * writable -- built without -z now), dynamic.
 *
 * Harder than, and structurally different from, both of this corpus's
 * other format-string targets (05's read-only PIE leak and 06's
 * single-variable 2-byte gate write): here the target is `puts@got`
 * itself, and the full 8-byte address must be assembled from several
 * 2-byte %N$hn writes at increasing byte offsets (the standard
 * "fmtstr_payload"-style multi-write GOT overwrite), each with its own
 * printed-character-count and embedded-NUL-ordering constraints. Once
 * puts@got is overwritten with win()'s address, the very next call to
 * puts() already present later in vuln() executes win() instead. win()
 * itself uses a raw write() syscall rather than puts() so the hijacked
 * GOT entry does not recursively call itself.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* The flag is intentionally NOT compiled into this binary (no literal in
 * .rodata that `strings`/ELF.search() could find with zero exploitation).
 * It is generated fresh per build by build_all_r2.sh and written to
 * flag.txt alongside the binary; win() reads it at runtime only after the
 * real bug has actually been exploited. Uses raw read()/write() (not
 * fopen()/puts()) so the hijacked puts@got entry can't recursively call
 * itself when win() needs to print. */
void win(void) {
    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0) {
        const char *msg = "flag.txt missing\n";
        write(1, msg, strlen(msg));
        return;
    }
    char flag[256];
    ssize_t n = read(fd, flag, sizeof(flag) - 1);
    close(fd);
    if (n > 0) write(1, flag, (size_t)n);
}

void vuln(void) {
    char buf[256];

    printf("msg: ");
    fflush(stdout);
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n < 0) n = 0;
    buf[n] = '\0';

    printf(buf); /* direct format-string vulnerability */
    putchar('\n');
    fflush(stdout);

    puts("post-leak checkpoint"); /* redirected to win() once puts@got is hijacked */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== r2-12 fmtstr-got-overwrite ===");
    vuln();
    puts("done");
    return 0;
}
