/*
 * Subprocess-injection corpus -- ANCHOR.
 *
 * The category: text the operator controls is concatenated into a command string
 * that is then handed to a sink which interprets SHELL METACHARACTERS. Nothing
 * in the program is memory-unsafe; the defect is entirely that untrusted bytes
 * cross into a shell's grammar.
 *
 * This is the first non-memory-safety category in this corpus set, and it is
 * here because the brief is binary AND software vulnerabilities: no canary, no
 * ASLR, no NX and no RELRO has any bearing on it (see `cflags`).
 *
 * VARIES FROM THE ANCHOR: nothing (this is the fixed point of the family).
 *
 * FLAG{supwngo_bench_inject_10_system_baseline}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROMPT "netcheck> "

/* THE DEFECT: `host` is operator-controlled and is pasted straight into a
 * string handed to system(), which runs it through /bin/sh -c. Any shell
 * metacharacter in `host` is therefore executed, not quoted. */
static int check_host(const char *host)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "/bin/echo checking %s", host);
    return system(cmd);
}

int main(void)
{
    char line[128];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("netcheck 1.0 -- type a host to check, or `exit`");
    for (;;) {
        fputs(PROMPT, stdout);
        if (fgets(line, sizeof(line), stdin) == NULL)
            break;
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '\0')
            continue;
        if (strcmp(line, "exit") == 0)
            break;
        check_host(line);
    }
    return 0;
}
