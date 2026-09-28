/* A two-function target used to prove `--win`/`--ret2`/`--rop` REDIRECT the
 * payload, by giving the overrides somewhere to point that is not where
 * auto-detection points.
 *
 * READ THIS BEFORE USING IT AS A "DETECTION FINDS NOTHING" FIXTURE -- IT IS
 * NOT ONE. That was this file's original intent and it was MEASURED WRONG:
 * `stage_two` matches nothing in `profile_stage.WIN_FUNCTIONS` and none of the
 * substrings the walkthrough's stricter scan wants, so the name-based pass does
 * miss it -- but `WinFunctionFinder._find_by_calls` finds ANY function that
 * calls `system`/`execve`, and this one calls `system("/bin/sh")`. Measured:
 * `solve --strategy ret2win` with NO `--win` SUCCEEDS here, targeting
 * `stage_two` at 0x4011d6. A negative control built on this fixture would pass
 * for the wrong reason.
 *
 * What it IS good for is redirection, where auto-detection succeeding is the
 * point -- it gives the test a baseline address to differ from:
 *
 *   auto                      -> 0x4011d6 (stage_two)  SUCCESS
 *   --win handle              -> 0x4011f7 (handle)     fails, correctly
 *   --ret2 handle             -> 0x4011f7 (handle)
 *   --ret2 handle --rop       -> 0x4011d6 (auto)       gadget, not a target
 *
 * The `--win handle` row is the useful one: the address in the generated script
 * changes, and the run then FAILS rather than quietly reverting to the address
 * detection preferred. Both halves matter -- an override that is honoured but
 * silently undone on failure would look identical to one that works.
 *
 * The overflow is deliberately trivial (an unbounded `read()` into a 64-byte
 * frame) so that nothing about the delivery can explain a difference in
 * outcome between two runs of the same technique.
 *
 * Build:
 *   gcc -fno-stack-protector -no-pie -z execstack -O0 \
 *       -o unnamed_payoff unnamed_payoff.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void stage_two(void)
{
    /* The payoff. Spawns a shell so verification can reach SHELL_ACCESS
     * without depending on a planted flag file. */
    system("/bin/sh");
    _exit(0);
}

void handle(void)
{
    char buf[64];
    puts("data?");
    fflush(stdout);
    read(0, buf, 512);   /* 512 into 64: the classic unbounded overflow */
    puts("ok");
    fflush(stdout);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    handle();
    return 0;
}
