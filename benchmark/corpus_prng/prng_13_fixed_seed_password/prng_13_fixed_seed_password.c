/*
 * Predictable-PRNG-secret variant corpus -- variant.
 *
 * THIS TARGET'S ONE PARTICULAR: the seed is a FIXED COMPILE-TIME CONSTANT and
 * the secret is a STRING compared with strcmp(), not a number.
 *   seed source      a literal, 0xC0FFEE
 *   generator        rand()
 *   draws to predict 8 (one per password character)
 *   what it guards   a login comparison (strcmp of an 8-character password)
 *   leaked output    none
 *
 * The password is generated, not stored, which is exactly what makes this look
 * defensible from the outside: there is no password string anywhere in the
 * image for `strings` to find. It is still the same defect -- a fixed seed
 * makes the "generated" password a constant of the binary, so every
 * installation shares one password and reproducing it needs nothing but the
 * seed and the alphabet.
 *
 * The alphabet is a real .rodata string here rather than arithmetic on the raw
 * draw. That is the honest shape (`ALPHABET[rand() % n]` is how this is
 * actually written) and it means an attacker recovers the character mapping
 * from the image rather than guessing an encoding.
 *
 * The flag is read from ./flag.txt on a successful strcmp and is never
 * compiled in.
 *
 * FLAG{supwngo_bench_prng_13_fixed_seed_password}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TRIES 8
#define PW_LEN 8
#define FIXED_SEED 0xC0FFEE

static const char ALPHABET[] = "abcdefghijklmnopqrstuvwxyz0123456789";

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
    char password[PW_LEN + 1];
    char line[64];
    int i, tries = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* The whole defect: a constant seed makes a "generated" password a
     * constant of the binary. */
    srand(FIXED_SEED);
    for (i = 0; i < PW_LEN; i++)
        password[i] = ALPHABET[rand() % (int)(sizeof ALPHABET - 1)];
    password[PW_LEN] = '\0';

    puts("=== maintenance login ===");
    printf("password, %d tries: \n", MAX_TRIES);

    while (tries < MAX_TRIES && fgets(line, sizeof line, stdin) != NULL) {
        size_t n = strlen(line);
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        tries++;
        if (strcmp(line, password) == 0) {
            puts("[+] login accepted");
            print_flag();
            return 0;
        }
        printf("[-] rejected (%d/%d)\n", tries, MAX_TRIES);
    }

    puts("[-] account locked");
    return 1;
}
