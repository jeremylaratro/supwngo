/*
 * Predictable-PRNG-secret variant corpus -- variant.
 *
 * THIS TARGET'S ONE PARTICULAR: the SEED SOURCE is getpid(), not time(NULL).
 *   seed source      getpid()            <-- the variable
 *   generator        rand()
 *   draws to predict 1
 *   what it guards   a 6-digit numeric PIN (rand() % 1000000)
 *   leaked output    none
 *
 * Everything else matches the anchor. A local attacker who launches the
 * process knows its pid exactly (fork() returns it), so unlike time(NULL)
 * there is no bracket to sweep: the seed is a single known value and the PIN
 * follows from it with no search at all.
 *
 * The truncation to six digits is deliberate: it shrinks the value space to
 * 10^6, which is why the try allowance here is 3 and not 64. Three tries
 * against 10^6 leaves blind guessing at 3e-6, so a pass still has to have
 * come from reproducing the draw.
 *
 * The flag is read from ./flag.txt at the moment the comparison succeeds and
 * is never compiled in.
 *
 * FLAG{supwngo_bench_prng_11_getpid_seed_pin}
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_TRIES 3
#define PIN_MOD 1000000

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
    int pin;
    char line[64];
    int tries = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    /* The whole defect: the pid is not a secret to whoever started us. */
    srand((unsigned int)getpid());
    pin = rand() % PIN_MOD;

    puts("=== device PIN gate ===");
    printf("6-digit PIN, %d tries: \n", MAX_TRIES);

    while (tries < MAX_TRIES && fgets(line, sizeof line, stdin) != NULL) {
        int guess = atoi(line);
        tries++;
        if (guess == pin) {
            puts("[+] PIN accepted");
            print_flag();
            return 0;
        }
        printf("[-] rejected (%d/%d)\n", tries, MAX_TRIES);
    }

    puts("[-] device locked");
    return 1;
}
