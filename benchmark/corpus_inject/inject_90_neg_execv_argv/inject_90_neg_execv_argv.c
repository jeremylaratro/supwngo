/*
 * Subprocess-injection corpus -- NEGATIVE CONTROL.
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
 * VARIES FROM THE ANCHOR: the command is built as an ARGV VECTOR and run with execv,
 * so no shell is involved and no byte of `host` is ever parsed as
 * grammar. This target must NOT be solved; if it is, the corpus is
 * measuring something other than the defect.
 *
 * FLAG{supwngo_bench_inject_90_neg_execv_argv}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROMPT "netcheck> "

#include <sys/wait.h>

/* THE CONTROL: byte-for-byte the anchor's job, done safely. `host` is passed as
 * its own argv element to execv, so /bin/echo receives it as one literal
 * argument. There is no shell in the path, so ';', '$(', '`' and friends are
 * just characters. */
static int check_host(const char *host)
{
    char *argv[4];
    pid_t pid;
    int status;

    argv[0] = (char *)"/bin/echo";
    argv[1] = (char *)"checking";
    argv[2] = (char *)host;
    argv[3] = NULL;

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        execv(argv[0], argv);
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
