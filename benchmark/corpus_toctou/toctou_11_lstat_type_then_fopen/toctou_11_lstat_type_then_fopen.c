/*
 * toctou_11_lstat_type_then_fopen -- FLAG{supwngo_bench_toctou_11_lstat_type_then_fopen}
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
 * THIS TARGET'S CHECK/USE PAIR: lstat() -> fopen(). The check does NOT follow
 * symlinks, so unlike the anchor it never resolves the secret at all -- what stops
 * a statically planted symlink here is the TYPE test (S_ISLNK is refused outright),
 * not an identity test, and the identity test it does carry compares the link's own
 * inode rather than its target's. The use is buffered stdio rather than a raw
 * descriptor, and fopen() follows symlinks exactly as open() does. An executor
 * that hardcoded "the check resolves the symlink, so the check is what I must
 * dodge" still works here; one that hardcoded the raw-open response shape, or that
 * assumed the check would reject a swapped-in link on IDENTITY, does not.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQDIR "/tmp/supwngo_toctou_11"
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

/* THE CHECK. One lstat() of the path the operator named. Because lstat() does not
 * follow symlinks, S_ISREG is doing the work a symlink would otherwise slip past;
 * the (dev, ino) test still runs, but on a symlink it compares the LINK's inode,
 * which is why the type test is the barrier in this variant. */
static const char *check_request(const char *path)
{
    struct stat want, got;

    if (!secret_path[0] || stat(secret_path, &want) != 0)
        return "cannot check";
    if (lstat(path, &got) != 0)
        return "cannot check";
    if (!S_ISREG(got.st_mode))
        return "not a plain file";
    if (got.st_nlink != 1)
        return "extra links";
    if (got.st_dev == want.st_dev && got.st_ino == want.st_ino)
        return "protected secret";
    return NULL;
}

static void serve(const char *name, const char *path)
{
    char buf[1024];

    /* THE USE. A SECOND resolution of the same path string, this time through
     * buffered stdio. fopen() follows whatever symlink is there NOW. */
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
    printf("supwngo request service (check: lstat, use: fopen)\n");
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
