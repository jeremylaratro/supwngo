/*
 * trav_13_absolute_path_accepted -- FLAG{supwngo_bench_trav_13_absolute_path_accepted}
 *
 * Family: benchmark/corpus_traversal/ -- PATH TRAVERSAL leading to ARBITRARY FILE
 * READ (CWE-22). The program joins operator-supplied text onto a fixed request
 * directory and opens the result by NAME, so a name that resolves upwards reaches
 * files the program believes it cannot reach. Nothing overflows, no pointer is
 * written, no code address is ever needed: the whole payload is a filename.
 *
 * HELD IDENTICAL ACROSS EVERY TARGET IN THE FAMILY
 *
 *   * the security goal    serve only files that are INSIDE the request
 *                          directory. The protected secret (flag.txt) sits beside
 *                          the BINARY, and the request directory is somewhere else
 *                          entirely (/tmp), so containment is the ONLY barrier
 *                          between a request and the secret. Every target states
 *                          that policy and every positive fails to enforce it;
 *   * the request protocol one operator-supplied NAME per iteration, read with
 *                          fgets() from stdin into a 512-byte line buffer, in an
 *                          UNBOUNDED loop -- so the attacker gets as many attempts
 *                          as it wants without restarting the process, and a
 *                          vocabulary of escapes can be tried in one session;
 *   * the secret's path    resolved ABSOLUTELY at startup from /proc/self/exe and
 *                          then stat()ed, and the program REFUSES TO RUN if that
 *                          stat fails. See "WHAT THE FAIL-CLOSED STAT IS AND IS
 *                          NOT" below -- it is a deployment assertion, deliberately
 *                          NOT an identity blacklist, and the reason is stated
 *                          rather than left implied;
 *   * the request dir      one per slug, /tmp/supwngo_trav_<NN>, never shared, so
 *                          two targets can be measured concurrently without
 *                          touching each other's filesystem state;
 *   * the win condition    the secret's bytes appear on the TARGET's stdout. The
 *                          attacker never opens the secret itself; it only names
 *                          it in a way the target's filter fails to refuse;
 *   * the protections      PIE + canary + NX + Full RELRO, from a cflags file that
 *                          is byte-identical across the whole family.
 *
 * THE ONE VARIABLE IN THIS FAMILY IS WHICH FLAWED CONTAINMENT FILTER THE ESCAPE
 * HAS TO DEFEAT -- what the program does to the name before it trusts it, and
 * therefore what shape of name gets through.
 *
 * WHAT THE FAIL-CLOSED STAT IS AND IS NOT
 *
 * locate_secret() resolves flag.txt's absolute path from /proc/self/exe and stat()s
 * it; main() exits non-zero if that fails. That is a DEPLOYMENT ASSERTION: it makes
 * "0 flag reads" impossible to confuse with "the planted secret was missing", and it
 * means no cwd or $PATH trick can silently remove the thing the measurement is
 * about. It is deliberately NOT used as a per-filename or (dev, ino) blacklist,
 * because this family's security goal is CONTAINMENT -- "only files inside the
 * request directory" -- and a one-filename blacklist would be a different, weaker
 * policy that happens to be defeated by the same traversal anyway (the constructed
 * string /tmp/.../../../<abs>/flag.txt is not equal to <abs>/flag.txt). Stating the
 * barrier honestly matters more than making the startup stat look load-bearing:
 * containment is the whole barrier, and each positive breaks it in a different way.
 *
 * THIS TARGET'S FILTER: ".." IS REJECTED OUTRIGHT, AND A LEADING '/' IS HONOURED.
 *
 * The parent-reference route is closed here, and closed properly -- any name
 * containing ".." anywhere is refused before anything is built, so every "../"
 * spelling that wins on trav_10, trav_11 and trav_12 is refused on this one. What is
 * open instead is the OTHER way out of a directory: not going up, but never entering
 * it. The program treats a name that begins with '/' as "already a full path" and
 * uses it verbatim instead of joining it:
 *
 *     name    "notes/today"        ->  "/tmp/supwngo_trav_13/notes/today"
 *     name    "/etc/passwd"        ->  "/etc/passwd"
 *
 * This is not a contrived shape. It is precisely the documented behaviour of
 * os.path.join() in Python, path.join() in Node, Path.Combine() in .NET and
 * filepath.Join()'s absolute-argument handling in many hand-rolled wrappers: an
 * absolute second component DISCARDS the base. Programs that reason about traversal
 * purely in terms of ".." are routinely wrong here, because no parent reference is
 * involved at all -- the request simply never was relative to the request directory.
 *
 * An exploit whose whole vocabulary is "go up" fails on this target; one that also
 * knows "start at the root" does not. The defect class -- operator text reaching a
 * path-based open with containment unenforced -- is unchanged.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The directory operators put request files in. A fixed ABSOLUTE path -- which is
 * what makes the family's request protocol identical across targets -- and
 * per-slug, so two targets never contend for the same name. It is deliberately NOT
 * beside the binary: the secret is beside the binary, so "inside this directory"
 * and "the secret" are disjoint by construction, and the only way to bridge them is
 * to escape the directory. */
#define REQDIR "/tmp/supwngo_trav_13"
#define SECRET_NAME "flag.txt"

/* Absolute path of the protected secret, resolved once at startup. Read only by the
 * startup assertion -- see the header. */
static char secret_path[4096];

static int locate_secret(void)
{
    char exe[4096];
    struct stat st;
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0)
        return -1;
    exe[n] = 0;
    char *slash = strrchr(exe, '/');
    if (!slash)
        return -1;
    *slash = 0;
    snprintf(secret_path, sizeof secret_path, "%s/%s", exe, SECRET_NAME);
    if (stat(secret_path, &st) != 0)
        return -1;              /* FAIL CLOSED: refuse to run at all. */
    return 0;
}

/* Serve a request by NAME. One open() of a path string, from scratch. */
static void serve(const char *name, const char *path)
{
    char buf[1024];

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        puts("denied: cannot open");
        return;
    }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    printf("--- %s ---\n%s\n", name, buf);
}

int main(void)
{
    char line[512];
    char path[4096];

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (locate_secret() != 0) {
        puts("fatal: protected file is not where it belongs; refusing to serve");
        return 1;
    }
    mkdir(REQDIR, 0777);
    printf("supwngo note service (filter: \"..\" rejected, absolute names honoured)\n");
    printf("request dir: %s\n", REQDIR);
    printf("only files inside the request dir may be served\n");

    for (;;) {
        printf("name> ");
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin))
            break;
        line[strcspn(line, "\n")] = 0;
        if (!line[0])
            continue;
        if (!strcmp(line, "quit"))
            break;

        /* The parent-reference route, closed. This part of the filter WORKS: no
         * spelling of ".." gets past it, because it is the two-character sequence
         * itself that is refused rather than any composite like "../". */
        if (strstr(line, "..")) {
            puts("denied: no parent references");
            continue;
        }

        /* THE DEFECT. An "already absolute" name is honoured verbatim, so the
         * request directory is simply not applied. Containment is asserted by the
         * join in the else-branch and by nothing else, and this branch does not
         * join. */
        if (line[0] == '/')
            snprintf(path, sizeof path, "%s", line);
        else
            snprintf(path, sizeof path, "%s/%s", REQDIR, line);

        serve(line, path);
    }
    return 0;
}
