/*
 * Indirect-call-hijack corpus, group (a) -- where the pointer lives.
 *
 * The category: a function pointer that the program later CALLS is reachable
 * from attacker-controlled bytes. The hijack lands on a live call site, not on a
 * saved return address, so it fires in the middle of a function and a stack
 * canary never gets a chance to notice.
 *
 * VARIES FROM THE ANCHOR: the struct is a LOCAL, so the pointer sits on the stack
 * rather than on the heap. Same member order (guaranteed by the
 * language), same overflow, different memory region.
 *
 * FLAG{supwngo_bench_fnptr_11_stack_struct}
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
    struct job j;

    setvbuf(stdout, NULL, _IONBF, 0);
    j.action = show;

    fputs("job name: ", stdout);
    /* THE DEFECT: as the anchor, but the overflowed pointer is a stack slot. */
    read(0, j.name, READ_LEN);

    j.action(j.name);
    return 0;
}
