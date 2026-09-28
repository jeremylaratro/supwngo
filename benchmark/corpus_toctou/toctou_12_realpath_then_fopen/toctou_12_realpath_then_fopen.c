/*
 * toctou_12_realpath_then_fopen -- FLAG{supwngo_bench_toctou_12_realpath_then_fopen}
 *
 * Family: benchmark/corpus_toctou/ -- a time-of-check-to-time-of-use file race.
 * The program checks a property of a PATH and then acts on the SAME PATH STRING
 * as a separate operation, so what the name points at can be swapped between the
 * two. Held IDENTICAL across every target in the family:
 *
 *   * the security goal    a request may only be served from a file that is
 *                          inside the request directory, is a PLAIN file, has
 *                          exactly ONE link, and is not the protected secret
 *                          (flag.txt, which sits beside the binary and therefore
 *                          OUTSIDE the request directory);
 *   * the request protocol one operator-supplied NAME per iteration, read with
 *                          fgets() from stdin in an UNBOUNDED loop, so the
 *                          attacker gets as many attempts as it wants without
 *                          restarting the process;
 *   * the name filter      "..", a leading '/' and any interior '/' are rejected,
 *                          so there is no path-traversal route at all and every
 *                          escape has to come from the race itself;
 *   * the secret's path    resolved ABSOLUTELY at startup from /proc/self/exe,
 *                          and the program FAILS CLOSED if it cannot be stat'd --
 *                          so no cwd trick can quietly switch the barrier off;
 *   * the st_nlink == 1    the request directory (under /tmp) and the secret are
 *     rule                 on the SAME filesystem on the reference host
 *                          (MEASURED: a plain os.link() across them succeeds), so
 *                          WITHOUT this rule a HARD LINK would serve the secret
 *                          with no race at all, and a racing exploit would be
 *                          credited for a non-race solve. It is part of the
 *                          family's constant policy for exactly that reason;
 *   * the split            no descriptor is ever carried from a check to the use.
 *                          Every action re-resolves a path STRING, so whatever
 *                          the name pointed at when it was checked -- or, where
 *                          nothing checks it, when it was created -- can differ
 *                          from what it points at when it is used;
 *   * the win condition    the secret's bytes appear on the TARGET's stdout. The
 *                          attacker never opens the secret; it only makes a name
 *                          point at it;
 *   * the protections      PIE + canary + NX + Full RELRO, from a cflags file
 *                          that is byte-identical across the whole family.
 *
 * THE ONE VARIABLE IN THIS FAMILY IS WHICH (CHECK, USE) OPERATION PAIR STRADDLES
 * THE WINDOW -- which API does the checking, which API does the acting, and
 * therefore what has to be swapped, and when.
 *
 * THIS TARGET'S CHECK/USE PAIR: realpath() -> fopen(). The canonicalise-then-use
 * shape. The check is CONTAINMENT rather than identity: realpath() collapses every
 * symlink and ".." in the name and the result must sit under the request directory,
 * which refuses a statically planted symlink no matter where it points, and the
 * stat() of the CANONICAL path refuses a hard link on st_nlink. Then the use
 * re-resolves the ORIGINAL, uncanonicalised string -- which is the whole bug, and
 * is what separates this variant from the others: an executor that learned "the
 * check reads metadata of the leaf" finds no leaf metadata call on the request
 * path at all here, and one that assumed the check and the use are handed the same
 * string finds that they are not.
 */
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQDIR "/tmp/supwngo_toctou_12"
#define SECRET_NAME "flag.txt"

static char secret_path[4096];

static void locate_secret(void)
{
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0)
        return;
    exe[n] = 0;
    char *slash = strrchr(exe, '/');
    if (!slash)
        return;
    *slash = 0;
    snprintf(secret_path, sizeof secret_path, "%s/%s", exe, SECRET_NAME);
}

/* THE CHECK. Canonicalise the operator's path, require the canonical form to sit
 * inside the request directory, and validate the canonical form's metadata. Every
 * part of the family policy is answered -- containment subsumes the identity test,
 * because the secret is outside the request directory by construction. */
static const char *check_request(const char *path)
{
    char resolved[PATH_MAX];
    struct stat got;

    if (!secret_path[0])
        return "cannot check";
    if (!realpath(path, resolved))
        return "cannot check";
    if (strncmp(resolved, REQDIR "/", sizeof(REQDIR "/") - 1) != 0)
        return "outside the request dir";
    if (stat(resolved, &got) != 0)
        return "cannot check";
    if (!S_ISREG(got.st_mode))
        return "not a plain file";
    if (got.st_nlink != 1)
        return "extra links";
    return NULL;
}

static void serve(const char *name, const char *path)
{
    char buf[1024];

    /* THE USE. The ORIGINAL, uncanonicalised string is resolved a second time --
     * so the canonical path that was validated is not the path that is opened. */
    FILE *fh = fopen(path, "r");
    if (!fh) {
        puts("denied: cannot open");
        return;
    }
    size_t n = fread(buf, 1, sizeof buf - 1, fh);
    fclose(fh);
    buf[n] = 0;
    printf("--- %s ---\n%s\n", name, buf);
}

int main(void)
{
    char line[256];
    char path[4096];

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(REQDIR, 0777);
    printf("supwngo request service (check: realpath, use: fopen)\n");
    printf("request dir: %s\n", REQDIR);

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
        if (strstr(line, "..") || strchr(line, '/')) {
            puts("denied: bad name");
            continue;
        }
        snprintf(path, sizeof path, "%s/%s", REQDIR, line);

        const char *why = check_request(path);
        if (why) {
            printf("denied: %s\n", why);
            continue;
        }

        serve(line, path);
    }
    return 0;
}
