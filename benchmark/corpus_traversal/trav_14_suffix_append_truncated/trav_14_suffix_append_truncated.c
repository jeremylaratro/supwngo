/*
 * trav_14_suffix_append_truncated -- FLAG{supwngo_bench_trav_14_suffix_append_truncated}
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
 * THIS TARGET'S FILTER: THE EXTENSION IS ENFORCED BY APPENDING IT, INTO A FIXED
 * BUFFER, AND snprintf() TRUNCATES.
 *
 * The policy this target adds is "only .txt notes are served", and it enforces that
 * the way it is enforced in the field -- not by validating the name but by APPENDING
 * ".txt" to whatever was typed. That is genuinely sound as a suffix rule: there is no
 * NUL-byte trick available (this is C, and the name arrives through fgets() into a
 * NUL-terminated buffer), and no second extension can be smuggled in. What is not
 * sound is the buffer it is appended INTO:
 *
 *     char path[256];
 *     snprintf(path, sizeof path, "%s/%s.txt", REQDIR, name);
 *
 * snprintf() is bounded and safe -- nothing overflows here, which is exactly why the
 * canary and NX in cflags have nothing to do -- but bounded means TRUNCATED, and what
 * gets truncated is whatever is at the END of the format: the ".txt" the policy
 * depends on. A name long enough to leave only 255 characters once the request
 * directory and the separator are accounted for pushes the suffix entirely off the
 * end, and the path that is opened is the operator's name verbatim.
 *
 * The attacker does not need the name to be long NATURALLY; padding a path with
 * no-op syntax is free. Extra '/' separators collapse during resolution, "./" is a
 * no-op, and "/.." at the root is defined to be the root again -- so the same file
 * can be named at any length above its minimum, to the byte. The escape is therefore
 * a length, and the program's own snprintf() size is the number to hit.
 *
 * The return value of snprintf() -- which is the number of characters the call WOULD
 * have written, and is exactly how a correct program detects this -- is discarded.
 * The family's negative control checks it.
 *
 * ONE HOST DEPENDENCE, STATED RATHER THAN HIDDEN: the padded name has to fit in the
 * 255 usable characters of `path` after "/tmp/supwngo_trav_14/", which leaves 234.
 * The shortest name that reaches the secret is the relative path from the request
 * directory to the binary's directory, so this target is exploitable only while that
 * relative path is shorter than 234 characters. Measured in this checkout it is 95,
 * leaving 139 characters of padding. A clone at a pathologically deep location would
 * make this variant UNSOLVABLE -- not wrongly solved, just out of reach -- and the
 * reference exploit reports the numbers it computed so that case is visible rather
 * than mysterious.
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
#define REQDIR "/tmp/supwngo_trav_14"
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
    /* Deliberately SMALLER than the 512-byte line buffer, and smaller than the
     * 4096-byte path buffer the rest of the family uses. This is the variable. */
    char path[256];

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (locate_secret() != 0) {
        puts("fatal: protected file is not where it belongs; refusing to serve");
        return 1;
    }
    mkdir(REQDIR, 0777);
    printf("supwngo note service (filter: \".txt\" appended, fixed 256-byte path)\n");
    printf("request dir: %s\n", REQDIR);
    printf("only .txt files inside the request dir may be served\n");

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

        /* THE DEFECT. The ".txt" restriction lives at the END of a bounded write,
         * so it is the first thing to be discarded when the write does not fit --
         * and the return value that would report exactly that is thrown away. */
        snprintf(path, sizeof path, "%s/%s.txt", REQDIR, line);
        serve(line, path);
    }
    return 0;
}
