/*
 * Predictable-PRNG-secret variant corpus -- ANCHOR.
 *
 * The category: a secret that guards something (authentication, a token, a
 * canary substitute, an address choice) is produced by the C library's
 * pseudo-random generator seeded from something the attacker can guess. The
 * generator is deterministic, so reproducing the seed reproduces the secret
 * EXACTLY -- the size of the secret's value space is irrelevant.
 *
 * THIS TARGET'S ONE PARTICULAR: the fixed point of the family.
 *   seed source      time(NULL)          -- known to within a second or two
 *   generator        rand()              -- glibc TYPE_3 additive feedback
 *   draws to predict 1 (the very first)
 *   what it guards   a numeric session-token comparison
 *   leaked output    none
 *
 * It exists so that a variant failure can be told apart from a corpus-wide
 * mistake. Every other target in this family changes exactly ONE of the five
 * lines above.
 *
 * Why 64 tries: the attacker cannot know which second the process started in,
 * so a bracket of candidate seeds around "now" must be testable inside one
 * connection. 64 tries against a 2^31 value space leaves blind guessing at
 * 3e-8 -- the allowance buys the seed bracket, not brute force.
 *
 * The flag is never compiled in: it is read from ./flag.txt at the moment the
 * comparison succeeds. `strings` on this binary yields nothing, so a solve
 * cannot be faked by reading .rodata (see SUPWNGO_BENCH_FLAG in
 * benchmark/build_all.sh).
 *
 * FLAG{supwngo_bench_prng_10_time_seed_token}
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MAX_TRIES 64

static void print_flag(void)
{
    FILE *f;
    char buf[128];

    f = fopen("flag.txt", "r");
    if (f == NULL) {
        puts("[-] flag.txt is missing");
        return;
    }
    if (fgets(buf, sizeof buf, f) != NULL)
        fputs(buf, stdout);
    fclose(f);
}

int main(void)
{
    unsigned int token;
    char line[64];
    int tries = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* The whole defect, in two lines. */
    srand((unsigned int)time(NULL));
    token = (unsigned int)rand();

    puts("=== session token gate ===");
    printf("token (decimal), %d tries: \n", MAX_TRIES);

    while (tries < MAX_TRIES && fgets(line, sizeof line, stdin) != NULL) {
        unsigned long guess = strtoul(line, NULL, 10);
        tries++;
        if (guess == (unsigned long)token) {
            puts("[+] token accepted");
            print_flag();
            return 0;
        }
        printf("[-] rejected (%d/%d)\n", tries, MAX_TRIES);
    }

    puts("[-] out of tries");
    return 1;
}
