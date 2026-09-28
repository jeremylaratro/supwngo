/*
 * sym_10_truncate_redirect -- FLAG{supwngo_bench_sym_10_truncate_redirect}
 *
 * Family: benchmark/corpus_symlink/ -- SYMLINK-FOLLOWING WRITE (CWE-59). A
 * program makes a write it considers routine -- logging an operator line to a
 * scratch file of its own choosing -- by resolving a FIXED, PREDICTABLE path
 * inside a directory the operator already writes into, with no O_NOFOLLOW and
 * no prior lstat()/stat()/access() of that name anywhere. Nothing ever asks
 * "what is currently at this name", so a symlink planted there before the
 * program starts is followed instead of refused, and the write lands
 * wherever the attacker pointed it.
 *
 * THIS TARGET, THE ANCHOR OF THE FAMILY: the redirected write TRUNCATES.
 * open(O_WRONLY | O_CREAT | O_TRUNC) on a path built by snprintf() from two
 * fixed literal components (the request directory and this target's own
 * scratch-file name) -- never a compile-time literal handed straight to
 * open(), which is what keeps this family structurally distinct from
 * benchmark/corpus_toctou/'s toctou_14 (see the module docstring in
 * supwngo/exploit/pipeline/executors/symlink_write_techniques.py for the
 * exact fact each gate needs).
 *
 * HELD IDENTICAL ACROSS THIS FAMILY (five positives + one control):
 *
 *   * the security goal    a write the program makes to its OWN scratch file
 *                          must never be able to land on policy.conf, the
 *                          file whose content gates disclosure of the secret;
 *   * the request protocol one operator-supplied LINE per iteration, read
 *                          with fgets() from stdin in an UNBOUNDED loop;
 *   * the request dir      /tmp/supwngo_sym_10, created (mkdir, return value
 *                          ignored, exactly like corpus_toctou) before the
 *                          request loop starts;
 *   * the gate file        REQDIR/policy.conf, (re)seeded with safe content
 *                          ("policy: LOCK") at startup via an FD-ANCHORED
 *                          openat() (directory opened once, leaf name never
 *                          built by snprintf) -- seeding is not the
 *                          vulnerable step, structurally as well as in
 *                          behaviour, and the gate's initial state is
 *                          deterministic every run;
 *   * the win condition    policy.conf's content contains "UNLOCK" -> the
 *                          program reads flag.txt (resolved at RUNTIME from
 *                          /proc/self/exe, never compiled in) and prints it;
 *   * the protections      PIE + canary + NX + Full RELRO, cflags
 *                          byte-identical to benchmark/corpus_toctou/'s.
 *                          Nothing here overflows, writes a return address,
 *                          or needs a code address -- the payload is a
 *                          symlink and a line of text, so the whole
 *                          mitigation stack is irrelevant to this category
 *                          for the same reason it is irrelevant to
 *                          corpus_toctou/.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQDIR "/tmp/supwngo_sym_10"
#define GATE_NAME "policy.conf"
#define OUTPUT_NAME "note.txt"
#define SECRET_NAME "flag.txt"
#define UNLOCK_MAGIC "UNLOCK"

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

/* FD-ANCHORED (mirrors benchmark/corpus_toctou/'s own negative control,
 * toctou_90_neg_fd_anchored): the directory is opened ONCE as a descriptor
 * and the leaf name is passed to openat() as a bare relative string, never
 * built by snprintf(). This is what makes seeding structurally OUTSIDE this
 * category's own join predicate (no snprintf call here at all to find),
 * not merely "a direct path" in comment only -- and it is why this function
 * has always been safe to call unconditionally: the gate's starting
 * content is deterministic every run regardless of what an attacker has
 * planted at the scratch-write's (unrelated) name. */
static void seed_gate(void)
{
    int dirfd = open(REQDIR, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0)
        return;
    int fd = openat(dirfd, GATE_NAME, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    close(dirfd);
    if (fd < 0)
        return;
    write(fd, "policy: LOCK\n", 13);
    close(fd);
}

/* THE BUG. A fixed, two-component path built at runtime by snprintf() --
 * never a literal handed to open() -- opened for writing with O_CREAT set
 * and O_NOFOLLOW clear. Nothing checks what NAME is currently there: no
 * stat(), no lstat(), no access(), nothing. */
static void write_output(const char *content)
{
    char path[4096];

    snprintf(path, sizeof path, "%s/%s", REQDIR, OUTPUT_NAME);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        puts("write: cannot open");
        return;
    }
    write(fd, content, strlen(content));
    write(fd, "\n", 1);
    close(fd);
}

/* The gate file is read back through its OWN direct, always-safe path (never
 * through the scratch-write's redirectable name), and its content decides
 * disclosure. */
static void check_gate(void)
{
    char path[4096];
    char buf[256];

    snprintf(path, sizeof path, "%s/%s", REQDIR, GATE_NAME);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        puts("gate: cannot read");
        return;
    }
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;

    if (!strstr(buf, UNLOCK_MAGIC)) {
        puts("gate: locked");
        return;
    }

    if (!secret_path[0]) {
        puts("gate: unlocked but no secret path");
        return;
    }
    int sfd = open(secret_path, O_RDONLY);
    if (sfd < 0) {
        puts("gate: unlocked but cannot open secret");
        return;
    }
    char sbuf[1024];
    ssize_t m = read(sfd, sbuf, sizeof sbuf - 1);
    close(sfd);
    sbuf[m > 0 ? m : 0] = 0;
    printf("unlocked: %s\n", sbuf);
}

int main(void)
{
    char line[256];

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(REQDIR, 0777);
    seed_gate();
    printf("supwngo scratch-write service (truncate)\n");
    printf("request dir: %s\n", REQDIR);

    for (;;) {
        printf("content> ");
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin))
            break;
        line[strcspn(line, "\n")] = 0;
        if (!line[0])
            continue;
        if (!strcmp(line, "quit"))
            break;
        write_output(line);
        check_gate();
    }
    return 0;
}
