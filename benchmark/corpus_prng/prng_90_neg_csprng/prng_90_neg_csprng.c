/*
 * Predictable-PRNG-secret variant corpus -- NEGATIVE CONTROL.
 *
 * This is prng_10_time_seed_token, the anchor, with ONE line changed: the token
 * comes from the kernel's CSPRNG (getrandom(2), falling back to /dev/urandom)
 * instead of from rand() seeded with time(NULL). Banner text, prompt text,
 * comparison, try allowance (64), flag path and protections are all identical,
 * so the only thing that differs between this target and the anchor is the
 * thing the category is ABOUT.
 *
 *   seed source      none -- there is no seed and no PRNG
 *   generator        getrandom(2), i.e. the kernel CSPRNG
 *   draws to predict 1, but it is not a draw from anything reproducible
 *   what it guards   the same numeric session-token comparison as the anchor
 *   leaked output    none
 *
 * WHY IT MUST NOT SOLVE. There is no seed to bracket: the token is independent
 * of the clock, of the pid, and of every previous run. Two runs in the same
 * second produce different tokens, where the anchor produces the same one --
 * that difference is the measurable signature the reference exploit checks,
 * rather than merely noting that this target is absent from the pass list.
 *
 * A technique that "solves" this one has not exploited a weak PRNG; it has
 * found some other way in (reading flag.txt directly, a lucky guess inside 64
 * tries at 3e-8, or a harness fault). Any of those invalidate every positive
 * result in this family, which is exactly what a control is for.
 *
 * FLAG{supwngo_bench_prng_90_neg_csprng}
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

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

/* The one changed line of the anchor, expanded: a real CSPRNG read, with a
 * /dev/urandom fallback so the control is still a control on a kernel without
 * getrandom(2). Masked to 31 bits so the value space is IDENTICAL to the
 * anchor's rand() range -- the control differs in unpredictability, not in
 * arithmetic. */
static unsigned int csprng_token(void)
{
    unsigned int v = 0;
    FILE *f;

    if (getrandom(&v, sizeof v, 0) == (ssize_t)sizeof v)
        return v & 0x7FFFFFFFu;

    f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        puts("[-] no entropy source");
        exit(1);
    }
    if (fread(&v, 1, sizeof v, f) != sizeof v) {
        puts("[-] short entropy read");
        exit(1);
    }
    fclose(f);
    return v & 0x7FFFFFFFu;
}

int main(void)
{
    unsigned int token;
    char line[64];
    int tries = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    token = csprng_token();

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
