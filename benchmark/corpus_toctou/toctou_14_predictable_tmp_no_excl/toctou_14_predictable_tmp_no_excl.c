/*
 * toctou_14_predictable_tmp_no_excl -- FLAG{supwngo_bench_toctou_14_predictable_tmp_no_excl}
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
 * THIS TARGET'S CHECK/USE PAIR: (nothing) -> open(O_WRONLY | O_CREAT) on a FIXED,
 * PREDICTABLE temp name, then a second open() of the same name to read it back.
 *
 * The operator's request path is handled SAFELY here, deliberately and to the same
 * standard as the family's negative control: one open() with O_NOFOLLOW and the
 * whole policy checked with fstat() on the DESCRIPTOR that open returned, so the
 * leaf race that wins on toctou_10/11/12 and the directory race that wins on
 * toctou_13 both fail on this target. What is left is the RESPONSE path: the
 * program stages every response through one hardcoded name under /tmp, opened with
 * O_CREAT but WITHOUT O_EXCL and WITHOUT O_TRUNC, and then reads that name back.
 * Nothing ever checks what the name already is, so there is no window to hit -- the
 * name can simply be a symlink before the program starts.
 *
 * So, stated plainly rather than rounded off: THIS VARIANT IS NOT A RACE. Its win
 * rate is 100% by construction and the measured numbers in the manifest say so.
 * It is in the family because CWE-377 (an insecure predictable temporary file) is
 * the same defect viewed with the window widened to infinity, and because it is
 * the one variant where "swap it between the two calls" is the wrong instinct:
 * there are no two calls to get between.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQDIR "/tmp/supwngo_toctou_14"
/* The predictable part. One fixed name, no mkstemp, no O_EXCL, never unlinked. */
#define STAGE "/tmp/supwngo_toctou_14_stage"
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

/* The request path, done RIGHT: a single resolution, and the policy answered from
 * the descriptor that resolution produced. There is no second resolution of the
 * request path anywhere in this target, so there is no window on it. */
static int open_checked(const char *path, const char **why)
{
    struct stat want, got;

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        *why = "cannot open";
        return -1;
    }
    if (!secret_path[0] || stat(secret_path, &want) != 0) {
        close(fd);
        *why = "cannot check";
        return -1;
    }
    if (fstat(fd, &got) != 0) {
        close(fd);
        *why = "cannot check";
        return -1;
    }
    if (!S_ISREG(got.st_mode)) {
        close(fd);
        *why = "not a plain file";
        return -1;
    }
    if (got.st_nlink != 1) {
        close(fd);
        *why = "extra links";
        return -1;
    }
    if (got.st_dev == want.st_dev && got.st_ino == want.st_ino) {
        close(fd);
        *why = "protected secret";
        return -1;
    }
    return fd;
}

static void serve(const char *name, const char *path)
{
    char buf[1024];
    char out[1024];
    const char *why = NULL;

    int fd = open_checked(path, &why);
    if (fd < 0) {
        printf("denied: %s\n", why);
        return;
    }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0)
        n = 0;

    /* THE BUG. A fixed, predictable name, created if absent and opened if not --
     * no O_EXCL, so an existing symlink is followed instead of refused, and no
     * O_TRUNC, so an empty response leaves whatever is on the other end intact. */
    int sfd = open(STAGE, O_WRONLY | O_CREAT, 0600);
    if (sfd < 0) {
        puts("denied: cannot stage");
        return;
    }
    if (n > 0) {
        if (write(sfd, buf, (size_t)n) < 0) {
            close(sfd);
            puts("denied: cannot stage");
            return;
        }
    }
    close(sfd);

    /* ... and read the staged response back by NAME, resolving it again. */
    int rfd = open(STAGE, O_RDONLY);
    if (rfd < 0) {
        puts("denied: cannot restage");
        return;
    }
    ssize_t m = read(rfd, out, sizeof out - 1);
    close(rfd);
    out[m > 0 ? m : 0] = 0;
    printf("--- %s ---\n%s\n", name, out);
}

int main(void)
{
    char line[256];
    char path[4096];

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(REQDIR, 0777);
    printf("supwngo request service (staged responses)\n");
    printf("request dir: %s\n", REQDIR);
    printf("stage file: %s\n", STAGE);

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
        serve(line, path);
    }
    return 0;
}
