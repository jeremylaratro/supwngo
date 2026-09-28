/*
 * Subprocess-injection corpus -- the injection position.
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
 * VARIES FROM THE ANCHOR: the controlled text lands in the MIDDLE of a pipeline, so
 * whatever is injected has to neutralise the trailing `| /bin/cat -` that
 * follows it -- a payload that simply appends a command runs it with its
 * stdout redirected into the tail of the pipe.
 *
 * FLAG{supwngo_bench_inject_14_suffix_pipeline}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROMPT "netcheck> "

/* Same defect, but the operator's text is not at the end of the command: a
 * pipeline stage follows it, and an injected command inherits that pipe unless
 * the payload terminates or comments out the remainder. */
static int check_host(const char *host)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd),
             "/bin/echo checking %s | /bin/cat -", host);
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
