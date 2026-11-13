/*
 * A dynamically linked program whose `main` has no symbol once it is
 * stripped (`gcc -s`). The only link from the entry point to the user code is
 * the first argument of the `__libc_start_main` call in `_start`, so a
 * default-function search must follow that argument
 * (selected_by == "libc_start_main_arg"); the entry function and the first
 * function reachable from it are both the wrong answer.
 *
 * `main` calls `puts` itself, so `puts` is a call the right function makes.
 */
#include <stdio.h>

int helper_value(int x)
{
    return x * 3 + 1;
}

int main(int argc, char **argv)
{
    (void)argv;
    puts("nomain_dyn");
    return helper_value(argc) > 100;
}
