/*
 * trav_90_neg_realpath_confined -- FLAG{supwngo_bench_trav_90_neg_realpath_confined}
 *
 * Family: benchmark/corpus_traversal/ -- PATH TRAVERSAL leading to ARBITRARY FILE
 * READ (CWE-22). THIS TARGET IS THE FAMILY'S NEGATIVE CONTROL: it has the same
 * shape, the same request protocol, the same secret in the same place and the same
 * byte-identical cflags as the five positives, and it is NOT exploitable. Its job is
 * to make a decline mean something -- if the family's one capability also "solved"
 * this, the capability could not be distinguished from doing nothing.
 *
 * HELD IDENTICAL ACROSS EVERY TARGET IN THE FAMILY
 *
 *   * the security goal    serve only files that are INSIDE the request
 *                          directory. The protected secret (flag.txt) sits beside
 *                          the BINARY, and the request directory is somewhere else
 *                          entirely (/tmp), so containment is the ONLY barrier
 *                          between a request and the secret. Every target states
 *                          that policy; this one actually enforces it;
 *   * the request protocol one operator-supplied NAME per iteration, read with
 *                          fgets() from stdin into a 512-byte line buffer, in an
 *                          UNBOUNDED loop -- so the attacker gets as many attempts
 *                          as it wants without restarting the process. The control
 *                          gives away exactly as many attempts as the positives;
 *   * the secret's path    resolved ABSOLUTELY at startup from /proc/self/exe and
 *                          then stat()ed, and the program REFUSES TO RUN if that
 *                          stat fails -- see the positives' headers for what that
 *                          assertion is and is not;
 *   * the request dir      one per slug, /tmp/supwngo_trav_90, never shared;
 *   * the win condition    the secret's bytes on the TARGET's stdout. Never
 *                          reachable here, which is the point;
 *   * the protections      PIE + canary + NX + Full RELRO, from a cflags file that
 *                          is byte-identical across the whole family. The control
 *                          sharing that file is what makes its refusal attributable
 *                          to the absence of the bug rather than to more hardening.
 *
 * REPAIRED THREE INDEPENDENT WAYS, SO IT IS NOT ONE PATCH FROM SOLVABLE
 *
 * A control that is one edit away from being a positive is a weak control: it tests
 * that one line exists, not that the class is closed. Each of the repairs below
 * independently defeats every escape the five positives use.
 *
 *   REPAIR 1 -- CANONICALISE, THEN CHECK CONTAINMENT ON THE RESOLVED PATH, THEN OPEN
 *               THE RESOLVED PATH. realpath(3) runs the kernel's own name resolver:
 *               it collapses every "..", every duplicated '/', every "./" and every
 *               symlink, and it fails outright for a path that does not exist. The
 *               containment test is then applied to that output -- and, critically,
 *               the string that is OPENED is that same output, not the string the
 *               operator helped build. There is no second, unchecked resolution for
 *               an escape to hide in. The test is `prefix == base_real` AND the next
 *               byte is '/', so "/tmp/supwngo_trav_90evil/x" cannot pass as a
 *               prefix match either. This alone defeats:
 *                 * trav_10/trav_12's plain "../" escape  (resolved path is outside)
 *                 * trav_11's "....//"                    (nothing named "...." exists,
 *                                                          so realpath fails first)
 *                 * trav_13's leading '/'                 (no absolute special case
 *                                                          exists here; the name is
 *                                                          always joined, so the
 *                                                          candidate is
 *                                                          /tmp/supwngo_trav_90//srv/...
 *                                                          which does not exist)
 *                 * trav_14's suffix truncation           (see REPAIR 3)
 *
 *   REPAIR 2 -- A STRICT SINGLE-COMPONENT ALLOWLIST. The name must be a non-empty
 *               run of [A-Za-z0-9._-] that does not begin with '.'. No '/', so the
 *               name cannot be a multi-component path at all; no leading '.', so
 *               ".." and "." are refused before the loop even looks at them. With
 *               this in place the candidate path always has exactly one component
 *               below the request directory, which makes escape impossible
 *               INDEPENDENTLY of REPAIR 1 -- delete the realpath() block entirely
 *               and there is still no name that leaves the directory. The only
 *               residual route would be a symlink planted inside the request
 *               directory, which is REPAIR 3's job.
 *
 *   REPAIR 3 -- FAIL CLOSED ON TRUNCATION, AND O_NOFOLLOW ON THE OPEN. snprintf()'s
 *               return value is checked against the buffer size and a request that
 *               would have been truncated is refused, so trav_14's "push the suffix
 *               off the end" has nothing to push (there is no appended suffix here
 *               either, but the check is what makes the class closed rather than
 *               absent). O_NOFOLLOW then refuses a symlink in the final component:
 *               after realpath() the canonical path contains no symlink by
 *               definition, so this closes the window between the canonicalisation
 *               and the open -- the one place a symlink swapped in by another
 *               process could still change what gets served. It is named honestly:
 *               O_NOFOLLOW does nothing against TRAVERSAL (it constrains only the
 *               final component, and a traversal escape needs no symlink at all);
 *               its value here is against the post-canonicalisation race.
 *
 * NEITHER $PATH, THE ENVIRONMENT, NOR THE WORKING DIRECTORY CAN INFLUENCE ANY OF IT.
 * There is no getenv() anywhere in this program. REQDIR is an absolute compile-time
 * constant, base_real is realpath(REQDIR) taken once at startup, every candidate is
 * built from base_real onwards, and realpath() of an absolute path never consults the
 * working directory. So an attacker who controls the environment or the cwd of the
 * process controls nothing that this program's decision depends on.
 *
 * THE INDEPENDENCE OF THE REPAIRS IS MEASURED, NOT ASSERTED
 *
 * "Repaired three independent ways" is a claim about what happens when one of them
 * is removed, and a claim like that is worth nothing unless it is exercised. So each
 * repair sits behind an ABLATION SWITCH that is NEVER defined by this family's
 * cflags -- the corpus binary always has all three -- and
 * benchmark/reference_exploits/traversal_variants_reference.py builds throwaway
 * copies with individual repairs disabled and re-runs the whole escape vocabulary
 * against them:
 *
 *   TRAV90_NO_ALLOWLIST     drop REPAIR 2  -> REPAIR 1 must still refuse everything
 *   TRAV90_NO_CANON         drop REPAIR 1  -> REPAIR 2 must still refuse everything
 *   TRAV90_NO_NOFOLLOW      drop O_NOFOLLOW
 *   TRAV90_NO_TRUNC_CHECK   drop the snprintf() truncation refusal
 *
 * and, as the POSITIVE CONTROL on that ablation, a build with ALL of them dropped,
 * which MUST become solvable. Without that last build, "the ablated binaries refused
 * everything" would be equally consistent with the ablation flags doing nothing at
 * all, or with the throwaway build being broken in some unrelated way.
 *
 * AND IT IS A GENUINELY WORKING PROGRAM, WHICH IS PART OF BEING A VALID CONTROL.
 * An "unsolvable" target that crashes on startup, or that refuses every request for
 * an unrelated reason (a missing request directory, a name filter nobody can
 * satisfy), is a BROKEN control: its zero flag reads would prove nothing about the
 * repairs. This one creates its request directory, serves any legitimate note inside
 * it, and says which files it can see -- so "it refused the escape" is separable from
 * "it refuses everything". The reference exploit asserts the legitimate service works
 * on this target before it asserts the escapes fail.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQDIR "/tmp/supwngo_trav_90"
#define SECRET_NAME "flag.txt"

/* Absolute path of the protected secret, resolved once at startup. Read only by the
 * startup assertion -- see the positives' headers. */
static char secret_path[4096];

/* realpath(REQDIR), taken once at startup. Every containment decision is made
 * against this, never against the compile-time spelling, so a symlinked /tmp or a
 * symlinked request directory cannot make a contained path look uncontained. */
static char base_real[4096];

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

/* REPAIR 2. A single path COMPONENT from a strict allowlist. */
static int legal_leaf(const char *name)
{
    size_t i;

    if (!name[0] || name[0] == '.')
        return 0;
    for (i = 0; name[i]; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

/* REPAIR 3, second half: no symlink in the final component.
 *
 * TRAV90_NO_NOFOLLOW is an ABLATION SWITCH and is never defined by this family's
 * cflags -- see "THE INDEPENDENCE OF THE REPAIRS IS MEASURED" in the header. */
#ifdef TRAV90_NO_NOFOLLOW
#define TRAV90_OPEN_FLAGS (O_RDONLY)
#else
#define TRAV90_OPEN_FLAGS (O_RDONLY | O_NOFOLLOW)
#endif

/* Serve a request. The path handed in here is the CANONICAL one -- see main(). */
static void serve(const char *name, const char *resolved)
{
    char buf[1024];

    int fd = open(resolved, TRAV90_OPEN_FLAGS);
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
    char cand[4096];
    char resolved[PATH_MAX];

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (locate_secret() != 0) {
        puts("fatal: protected file is not where it belongs; refusing to serve");
        return 1;
    }
    mkdir(REQDIR, 0777);
    if (!realpath(REQDIR, base_real)) {
        puts("fatal: cannot canonicalise the request directory; refusing to serve");
        return 1;
    }
    printf("supwngo note service (filter: realpath-confined, O_NOFOLLOW)\n");
    printf("request dir: %s\n", base_real);
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

        /* REPAIR 2. */
#ifndef TRAV90_NO_ALLOWLIST
        if (!legal_leaf(line)) {
            puts("denied: a request must be one plain file name");
            continue;
        }
#endif

        /* REPAIR 3, first half: snprintf() is bounded, and a bounded write that did
         * not fit is REFUSED rather than silently served short. */
        int n = snprintf(cand, sizeof cand, "%s/%s", REQDIR, line);
#ifndef TRAV90_NO_TRUNC_CHECK
        if (n < 0 || (size_t)n >= sizeof cand) {
            puts("denied: request too long");
            continue;
        }
#else
        (void)n;
#endif

        /* REPAIR 1. Canonicalise; then test containment on the RESULT; then open
         * the RESULT. `cand` -- the string the operator helped build -- is never
         * opened, so there is no second resolution to disagree with the check. */
#ifdef TRAV90_NO_CANON
        /* ABLATION ONLY: open the unresolved candidate, which is what the five
         * positives do. Never compiled into the corpus binary. */
        (void)resolved;
        serve(line, cand);
#else
        if (!realpath(cand, resolved)) {
            puts("denied: cannot resolve");
            continue;
        }
        size_t blen = strlen(base_real);
        if (strncmp(resolved, base_real, blen) != 0 || resolved[blen] != '/') {
            puts("denied: outside the request directory");
            continue;
        }

        serve(line, resolved);
#endif
    }
    return 0;
}
