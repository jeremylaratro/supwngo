/*
 * toctou_90_neg_fd_anchored -- FLAG{supwngo_bench_toctou_90_neg_fd_anchored}
 *
 * NEGATIVE CONTROL for benchmark/corpus_toctou/. It does the family's job -- serve
 * a named request file, refuse the protected secret -- with no window to race, and
 * it is built from the SAME byte-identical cflags as the four positives, so its
 * refusal is attributable to the bug's absence rather than to different hardening.
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
 *   * the win condition    the secret's bytes appear on the TARGET's stdout;
 *   * the protections      PIE + canary + NX + Full RELRO, from a cflags file
 *                          that is byte-identical across the whole family.
 *
 * The one thing NOT held identical here is the family's defining property: this
 * target never resolves a request path twice.
 *
 * THIS TARGET'S CHECK/USE PAIR: there isn't one, and the bug is repaired TWO
 * INDEPENDENT ways so the control is not one edit away from being a positive:
 *
 *   REPAIR 1  ONE resolution. open() is called once, and the entire policy is then
 *             answered with fstat() on the DESCRIPTOR that call returned -- so the
 *             bytes that are served are provably the bytes that were checked. There
 *             is no second path walk for a swap to land in. This is also the repair
 *             that covers a swapped-in DIRECTORY component (toctou_13's route):
 *             O_NOFOLLOW would happily follow it, but the fstat() identity test
 *             then sees the secret and refuses.
 *
 *   REPAIR 2  O_NOFOLLOW on that single open(). Even if a window existed and a
 *             symlink were swapped into the leaf position inside it, the open would
 *             fail with ELOOP rather than follow the link. This is the repair that
 *             covers the leaf race (toctou_10/11/12's route) on its own.
 *
 * Either repair alone defeats every route the family's positives use. Both are
 * present, so reverting one leaves the control still refusing -- which is the point
 * of a control whose refusal has to mean something.
 *
 * It also does NOT stage its responses through a predictable temporary name (see
 * toctou_14): the bytes go straight from the checked descriptor to stdout.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQDIR "/tmp/supwngo_toctou_90"
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

/* One resolution, then every policy question answered from the descriptor. */
static int open_checked(const char *path, const char **why)
{
    struct stat want, got;

    /* REPAIR 2: O_NOFOLLOW. A symlink in the final position is refused (ELOOP)
     * rather than followed, whether it was there all along or swapped in. */
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
    /* REPAIR 1: fstat on the DESCRIPTOR, not a second stat of the path. Nothing
     * the filesystem does after this open can change what this descriptor refers
     * to, so the checked object and the served object are the same object. */
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
    const char *why = NULL;

    int fd = open_checked(path, &why);
    if (fd < 0) {
        printf("denied: %s\n", why);
        return;
    }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    printf("--- %s ---\n%s\n", name, buf);
}

int main(void)
{
    char line[256];
    char path[4096];

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(REQDIR, 0777);
    printf("supwngo request service (single resolution, fd-anchored checks)\n");
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
        serve(line, path);
    }
    return 0;
}
