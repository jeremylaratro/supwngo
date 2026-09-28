/*
 * Predictable-PRNG-secret variant corpus -- variant.
 *
 * THIS TARGET'S ONE PARTICULAR: srand() is NEVER CALLED, and the secret is a
 * SEQUENCE rather than a single draw.
 *   seed source      none -- glibc starts rand() as if srand(1) had run
 *   generator        rand()
 *   draws to predict 5, consecutively, with no recovery from a wrong one
 *   what it guards   a "guess N in a row" game
 *   leaked output    none
 *
 * This is the degenerate end of the category and the reason "the seed looked
 * random enough" is never the right defence: with no srand() at all the
 * sequence is a CONSTANT of the C library, identical on every run of every
 * process on every machine with the same glibc. There is no seed to bracket
 * and no pid to observe.
 *
 * Five draws in a row is the point. One draw could be dismissed as luck
 * (2^-31); five cannot, and a partial-credit solve is impossible because a
 * single wrong round ends the process. So a pass here means the whole
 * sequence was reproduced, in order, from the generator -- not sampled.
 *
 * The flag is read from ./flag.txt after the fifth correct round and is never
 * compiled in.
 *
 * FLAG{supwngo_bench_prng_12_unseeded_sequence}
 */
#include <stdio.h>
#include <stdlib.h>

#define ROUNDS 5

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
    char line[64];
    int round;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* The whole defect: no srand() anywhere. The sequence below is a
     * compile-time-knowable constant of the C library. */
    puts("=== streak game: five in a row ===");

    for (round = 1; round <= ROUNDS; round++) {
        int expected = rand();
        int guess = -1;

        printf("round %d/%d: \n", round, ROUNDS);
        if (fgets(line, sizeof line, stdin) == NULL) {
            puts("[-] disconnected");
            return 1;
        }
        if (sscanf(line, "%d", &guess) != 1 || guess != expected) {
            printf("[-] wrong on round %d -- streak lost\n", round);
            return 1;
        }
        puts("[+] hit");
    }

    puts("[+] five in a row");
    print_flag();
    return 0;
}
