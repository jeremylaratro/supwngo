/*
 * Indirect-call-hijack corpus, group (a) -- NEGATIVE CONTROL.
 *
 * The category: a function pointer that the program later CALLS is reachable
 * from attacker-controlled bytes. The hijack lands on a live call site, not on a
 * saved return address, so it fires in the middle of a function and a stack
 * canary never gets a chance to notice.
 *
 * VARIES FROM THE ANCHOR: the read is bounded to the array it targets. The function
 * pointer is still there and is still called, but nothing the operator
 * sends can reach it. This target must NOT be solved.
 *
 * FLAG{supwngo_bench_fnptr_90_neg_bounded_read}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


void spawn_shell(void)
{
    system("/bin/sh");
}

#define NAME_LEN 32

struct job {
    char name[NAME_LEN];
    void (*action)(const char *);
};

static void show(const char *name)
{
    printf("job: %s\n", name);
}

int main(void)
{
    struct job *j;

    setvbuf(stdout, NULL, _IONBF, 0);
    j = malloc(sizeof(*j));
    if (j == NULL)
        return 1;
    j->action = show;

    fputs("job name: ", stdout);
    /* THE CONTROL: byte-for-byte the anchor, except the length is derived from
     * the destination array instead of being a separate constant. `action` is
     * unreachable. */
    read(0, j->name, sizeof(j->name) - 1);

    j->action(j->name);
    return 0;
}
