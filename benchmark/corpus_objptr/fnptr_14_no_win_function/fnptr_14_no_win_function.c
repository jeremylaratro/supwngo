/*
 * Indirect-call-hijack corpus, group (a) -- what is available to point at.
 *
 * The category: a function pointer that the program later CALLS is reachable
 * from attacker-controlled bytes. The hijack lands on a live call site, not on a
 * saved return address, so it fires in the middle of a function and a stack
 * canary never gets a chance to notice.
 *
 * VARIES FROM THE ANCHOR: there is NO win function in the image. The hijack has to
 * reach system@plt instead -- which works only because the call site passes
 * the overflowed buffer itself as the argument, so the same payload that
 * supplies the pointer also supplies "/bin/sh".
 *
 * FLAG{supwngo_bench_fnptr_14_no_win_function}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define NAME_LEN 32
#define READ_LEN 64

struct job {
    char name[NAME_LEN];
    void (*action)(const char *);
};

static void show(const char *name)
{
    printf("job: %s\n", name);
}

/* Present so that system() is linked and reachable through the PLT. Nothing in
 * this image spawns a shell on its own. */
static void audit(const char *name)
{
    (void)name;
    system("/bin/date");
}

/* Keeps `audit` from being discarded, and is const so it is not itself a target. */
static void (*const modes[2])(const char *) = { show, audit };

int main(void)
{
    struct job *j;

    setvbuf(stdout, NULL, _IONBF, 0);
    j = malloc(sizeof(*j));
    if (j == NULL)
        return 1;
    j->action = modes[0];

    fputs("job name: ", stdout);
    /* THE DEFECT: as the anchor. The difference is what can be reached: with no
     * win function, the pointer must become system@plt and the buffer must
     * simultaneously be a command string. */
    read(0, j->name, READ_LEN);

    j->action(j->name);
    return 0;
}
