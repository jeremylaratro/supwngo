/*
 * Subprocess-injection corpus -- the sink.
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
 * VARIES FROM THE ANCHOR: popen() instead of system(), and the child's output is read back
 * and reprinted, so the injected command's stdout returns by a different
 * route than the anchor's inherited stdout.
 *
 * FLAG{supwngo_bench_inject_11_popen_sink}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROMPT "netcheck> "

/* Same defect, different sink: popen() also runs its argument through
 * /bin/sh -c, but the child's stdout arrives on a pipe this function drains. */
static int check_host(const char *host)
{
    char cmd[256];
    char out[256];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "/bin/echo checking %s", host);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen");
        return 1;
    }
    while (fgets(out, sizeof(out), fp) != NULL)
        fputs(out, stdout);
    return pclose(fp);
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
