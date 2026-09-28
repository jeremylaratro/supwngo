/*
 * sym_12_dir_component_redirect -- FLAG{supwngo_bench_sym_12_dir_component_redirect}
 *
 * Family: benchmark/corpus_symlink/ -- SYMLINK-FOLLOWING WRITE (CWE-59). See
 * sym_10_truncate_redirect/sym_10_truncate_redirect.c for the family's full
 * shape (held identical here).
 *
 * THIS TARGET'S MECHANISM: the swappable name is a DIRECTORY COMPONENT, not
 * the final element. The scratch write goes to REQDIR/pending/policy.conf --
 * a THREE-component path (request dir, a fixed intermediate the program
 * itself inserts, and a leaf) -- rather than REQDIR/<leaf> directly. Under
 * normal operation this is a harmless file that happens to share a NAME with
 * the real gate file while living in a different directory (mirroring
 * benchmark/corpus_toctou/'s toctou_13_dir_component_swap, whose decoy is
 * deliberately named flag.txt for the same reason). An attacker who replaces
 * "pending" itself with a symlink to REQDIR makes the identical leaf name
 * resolve to REQDIR/policy.conf -- the REAL gate file -- with no symlink in
 * the final position at all, and no check anywhere catches it because
 * (exactly as in every other target in this family) nothing ever checks what
 * is currently at the path.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQDIR "/tmp/supwngo_sym_12"
#define STAGE_COMPONENT "pending"
#define GATE_NAME "policy.conf"
/* Deliberately the SAME basename as GATE_NAME: this is what makes the
 * directory-component swap land the write exactly on the real gate file
 * rather than merely on some other file inside REQDIR. */
#define OUTPUT_NAME "policy.conf"
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

/* THE BUG. A runtime-constructed THREE-component path -- request dir, the
 * program's own fixed intermediate directory name, and a leaf -- opened for
 * writing with O_CREAT set and O_NOFOLLOW clear, no check anywhere. The
 * swappable name here is STAGE_COMPONENT, in the middle of the path, not the
 * leaf. */
static void write_output(const char *content)
{
    char path[4096];

    snprintf(path, sizeof path, "%s/%s/%s", REQDIR, STAGE_COMPONENT, OUTPUT_NAME);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        puts("write: cannot open");
        return;
    }
    write(fd, content, strlen(content));
    write(fd, "\n", 1);
    close(fd);
}

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
    char pending_path[4096];

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(REQDIR, 0777);
    snprintf(pending_path, sizeof pending_path, "%s/%s", REQDIR, STAGE_COMPONENT);
    mkdir(pending_path, 0777);
    seed_gate();
    printf("supwngo scratch-write service (dir component)\n");
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
