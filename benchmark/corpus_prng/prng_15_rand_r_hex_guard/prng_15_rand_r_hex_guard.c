/*
 * Predictable-PRNG-secret variant corpus -- variant.
 *
 * THIS TARGET'S ONE PARTICULAR: a DIFFERENT GENERATOR -- rand_r(), whose state
 * is a plain unsigned int the caller holds -- and the answer is given in HEX.
 *   seed source      time(NULL), stored into the caller's own state word
 *   generator        rand_r()  -- glibc's three-step LCG, NOT the TYPE_3
 *                    additive-feedback generator behind rand()/random()
 *   draws to predict 1
 *   what it guards   a 32-bit "session guard" word -- the canary substitute a
 *                    program invents when it wants an unpredictable cookie
 *   leaked output    none
 *
 * Two things make this its own case. First, rand_r() is a completely different
 * algorithm from rand(): an exploit that models glibc's TYPE_3 generator
 * produces the wrong value here, so a tool must decide WHICH generator it is
 * facing rather than assume one. Second, the guard is consumed in hex
 * (strtoul(line, NULL, 16)), so the answer's ENCODING differs even when the
 * predicted number is right -- and that base is recoverable from the image,
 * since -O0 leaves it as the literal third argument of the strtoul call.
 *
 * Calling this a canary substitute is the point of the framing: rand_r() here
 * is doing the job a real stack cookie does, and it is doing it out of a clock.
 *
 * The flag is read from ./flag.txt when the guard matches and is never compiled
 * in.
 *
 * FLAG{supwngo_bench_prng_15_rand_r_hex_guard}
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
    unsigned int state;
    unsigned int guard;
    char line[64];
    int tries = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* The whole defect: the cookie that stands in for a canary comes out of
     * the clock, through a generator with a 32-bit caller-visible state. */
    state = (unsigned int)time(NULL);
    guard = (unsigned int)rand_r(&state);

    puts("=== guarded region ===");
    printf("session guard (hex), %d tries: \n", MAX_TRIES);

    while (tries < MAX_TRIES && fgets(line, sizeof line, stdin) != NULL) {
        unsigned long guess = strtoul(line, NULL, 16);
        tries++;
        if (guess == (unsigned long)guard) {
            puts("[+] guard matched");
            print_flag();
            return 0;
        }
        printf("[-] rejected (%d/%d)\n", tries, MAX_TRIES);
    }

    puts("[-] region sealed");
    return 1;
}
