/*
 * sym_14_fopen_redirect -- FLAG{supwngo_bench_sym_14_fopen_redirect}
 *
 * Family: benchmark/corpus_symlink/ -- SYMLINK-FOLLOWING WRITE (CWE-59). See
 * sym_10_truncate_redirect/sym_10_truncate_redirect.c for the family's full
 * shape (held identical here).
 *
 * THIS TARGET'S MECHANISM: the write goes through buffered stdio -- fopen()
 * with mode "w" and fputs()/fclose() -- rather than a raw open()/write().
 * Standard C's <stdio.h> has no O_NOFOLLOW equivalent at any mode string, so
 * this is the fopen-family counterpart to sym_13's creat(): the API itself
 * cannot express "refuse to follow a symlink" no matter how it is called.
 * (Mirrors benchmark/corpus_toctou/'s own toctou_11_lstat_type_then_fopen,
 * which varies the USE side the same way for the read-side category.)
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQDIR "/tmp/supwngo_sym_14"
#define GATE_NAME "policy.conf"
#define OUTPUT_NAME "stats.dat"
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

/* THE BUG. fopen(path, "w") on a runtime-constructed two-component path.
 * Buffered stdio has no O_NOFOLLOW equivalent to set, and nothing checks
 * what is currently at the name before this call resolves it. */
static void write_output(const char *content)
{
    char path[4096];

    snprintf(path, sizeof path, "%s/%s", REQDIR, OUTPUT_NAME);
    FILE *fp = fopen(path, "w");
    if (!fp) {
        puts("write: cannot open");
        return;
    }
    fputs(content, fp);
    fputc('\n', fp);
    fclose(fp);
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

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(REQDIR, 0777);
    seed_gate();
    printf("supwngo scratch-write service (fopen)\n");
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
