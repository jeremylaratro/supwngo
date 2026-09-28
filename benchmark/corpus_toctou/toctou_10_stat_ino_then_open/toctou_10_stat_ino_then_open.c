/*
 * toctou_10_stat_ino_then_open -- FLAG{supwngo_bench_toctou_10_stat_ino_then_open}
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
 * THIS TARGET'S CHECK/USE PAIR: stat() -> open(). This is the anchor. stat()
 * FOLLOWS symlinks, so a symlink left pointing at the secret is resolved and its
 * (st_dev, st_ino) matches the secret's, and the request is refused; a hard link
 * is refused on st_nlink. A static swap therefore cannot win -- the attacker has
 * to make the name a plain file at the instant stat() looks and a symlink at the
 * instant open() looks. The window is the handful of instructions between the two
 * syscalls.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The directory operators put request files in. A fixed absolute path -- which is
 * what makes the family's request protocol identical across targets -- and
 * per-slug, so two targets never contend for the same name. */
#define REQDIR "/tmp/supwngo_toctou_10"
#define SECRET_NAME "flag.txt"

/* Absolute path of the protected secret, resolved once at startup. */
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

/* THE CHECK. One stat() of the path the operator named, answering the whole
 * family policy: plain file, single link, and not the secret's (dev, ino).
 *
 * Returns 0 when the request is allowed, and non-zero (a reason string is printed
 * by the caller) when it is refused -- including when the question cannot be
 * answered at all, so a missing or unreadable secret file fails CLOSED rather
 * than disabling the barrier.
 */
static const char *check_request(const char *path)
{
    struct stat want, got;

    if (!secret_path[0] || stat(secret_path, &want) != 0)
        return "cannot check";
    if (stat(path, &got) != 0)
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

    /* THE USE. A SECOND resolution of the same path string: open() walks the
     * name again from scratch and follows whatever symlink is there NOW. */
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
    char line[256];
    char path[4096];

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(REQDIR, 0777);
    printf("supwngo request service (check: stat, use: open)\n");
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
