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
 * VARIES FROM THE ANCHOR: an explicit execl("/bin/sh", "-c", cmd) in a forked child
 * rather than the libc system() wrapper, so there is no system@plt to
 * recognise -- only a /bin/sh string and an exec.
 *
 * FLAG{supwngo_bench_inject_12_execl_dash_c}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROMPT "netcheck> "

#include <sys/wait.h>

/* Same defect with the wrapper spelled out by hand. There is no system@plt or
 * popen@plt in this image at all; the shell is reached through execl. */
static int check_host(const char *host)
{
    char cmd[256];
    pid_t pid;
    int status;

    snprintf(cmd, sizeof(cmd), "/bin/echo checking %s", host);
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    waitpid(pid, &status, 0);
    return status;
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
