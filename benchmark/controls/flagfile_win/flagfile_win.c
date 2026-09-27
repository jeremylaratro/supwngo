/*
 * POSITIVE CONTROL for scripts/htb_rescore.py -- not a corpus target.
 *
 * This is benchmark/corpus/15_win_function with exactly ONE thing changed:
 * win() reads the flag from ./flag.txt at runtime instead of printing a
 * compiled-in constant. Everything else -- the 32-byte buffer, the 200-byte
 * read, the protections, the win-function shape -- is deliberately identical,
 * so a difference in outcome between the two is attributable to the flag
 * source and to nothing else.
 *
 * Why it exists: htb_rescore.py attributes a solve by planting a per-rep
 * secret in a FILE (HTB binaries ship without source, so it cannot recompile
 * a secret in the way run_bench.py does). Every corpus target carries its flag
 * as a compiled-in string, so none of them can ever reproduce a planted
 * secret, and none can prove the harness's FLAG_CAPTURED branch is able to
 * fire. This target can.
 *
 * There is intentionally NO flag string in this binary. Checkable:
 *     strings flagfile_win | grep -E '(FLAG|HTB)\{'    # must be empty
 *
 * Protections (matching target 15): canary=OFF, NX=ON, PIE=OFF, RELRO=FULL.
 */
#include <stdio.h>
#include <unistd.h>

/* The flag path is relative on purpose: htb_rescore.py runs each rep with
 * cwd set to the throwaway workspace it planted the secret in, so "./flag.txt"
 * resolves to THIS rep's secret and cannot resolve to a stale one. */
void win(void) {
    char buf[128];
    FILE *f = fopen("flag.txt", "r");

    if (f == NULL) {
        /* Distinguishable from a wrong flag. If this line appears, the
         * control's environment is wrong -- the harness did not plant a
         * flag where this binary reads one -- which is a different failure
         * from "the pipeline did not reach win()". */
        puts("CONTROL-ERROR: no flag.txt in cwd");
        return;
    }
    if (fgets(buf, sizeof buf, f) != NULL) {
        fputs(buf, stdout);
    }
    fclose(f);
}

void vuln(void) {
    char buf[32];

    printf("Say something: ");
    fflush(stdout);
    read(0, buf, 200); /* buf is 32 bytes: no canary to stop the overflow */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== flagfile_win control ===");
    vuln();
    puts("done");
    return 0;
}
