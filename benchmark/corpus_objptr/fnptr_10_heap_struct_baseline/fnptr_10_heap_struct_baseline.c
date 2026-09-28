/*
 * Indirect-call-hijack corpus, group (a) -- ANCHOR.
 *
 * The category: a function pointer that the program later CALLS is reachable
 * from attacker-controlled bytes. The hijack lands on a live call site, not on a
 * saved return address, so it fires in the middle of a function and a stack
 * canary never gets a chance to notice.
 *
 * VARIES FROM THE ANCHOR: nothing (this is the fixed point of the group).
 *
 * FLAG{supwngo_bench_fnptr_10_heap_struct_baseline}
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
#define READ_LEN 64

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
    /* THE DEFECT: READ_LEN is twice sizeof(j->name), so bytes past the array
     * land on the adjacent `action` member -- which is then called. */
    read(0, j->name, READ_LEN);

    j->action(j->name);
    return 0;
}
