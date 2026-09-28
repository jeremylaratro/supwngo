/*
 * Predictable-PRNG-secret variant corpus -- variant.
 *
 * THIS TARGET'S ONE PARTICULAR: PRNG OUTPUT IS LEAKED to the attacker before
 * the secret is drawn, and the generator is reached through random() rather
 * than rand().
 *   seed source      time(NULL), via srandom()
 *   generator        random()  -- the same glibc TYPE_3 state rand() uses
 *   draws to predict the 4th; the first 3 are handed over
 *   what it guards   an auth token echoed back by the client
 *   leaked output    3 full 31-bit draws
 *
 * This is the strongest case in the family and the cheapest to exploit: the
 * seed does not have to be GUESSED at all, it is RECOVERED. Three consecutive
 * 31-bit outputs identify the seed uniquely in any practical candidate set, so
 * the attacker confirms the seed before spending a try -- and then knows every
 * future draw, not just the next one.
 *
 * It doubles as the positive control for an exploit's PRNG model: a generator
 * that does not reproduce glibc exactly can never match three leaked 31-bit
 * values, so a match is proof the model is right rather than an assumption.
 *
 * random()/srandom() rather than rand()/srand() is the other half of the
 * particular. They share one state in glibc -- identical outputs for identical
 * seeds -- so a tool that pattern-matches only on the name `rand` misses a
 * target that is bit-for-bit as predictable.
 *
 * The flag is read from ./flag.txt when the token matches and is never
 * compiled in.
 *
 * FLAG{supwngo_bench_prng_14_leak_then_recover}
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MAX_TRIES 4
#define NONCES 3

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
    long token;
    char line[64];
    int i, tries = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    srandom((unsigned int)time(NULL));

    puts("=== handshake ===");
    /* The whole defect: these come from the same stream as the token below,
     * so publishing them publishes the seed. */
    for (i = 0; i < NONCES; i++)
        printf("nonce %ld\n", random());

    token = random();

    printf("auth token (decimal), %d tries: \n", MAX_TRIES);

    while (tries < MAX_TRIES && fgets(line, sizeof line, stdin) != NULL) {
        long guess = strtol(line, NULL, 10);
        tries++;
        if (guess == token) {
            puts("[+] token accepted");
            print_flag();
            return 0;
        }
        printf("[-] rejected (%d/%d)\n", tries, MAX_TRIES);
    }

    puts("[-] handshake failed");
    return 1;
}
