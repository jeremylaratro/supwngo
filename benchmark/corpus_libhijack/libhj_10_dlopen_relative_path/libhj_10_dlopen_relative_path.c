/*
 * libhj_10_dlopen_relative_path
 *
 * Family: benchmark/corpus_libhijack/ -- UNTRUSTED LIBRARY SEARCH PATH.
 * CWE-426 (untrusted search path) / CWE-427 (uncontrolled search path element).
 * The program loads an extension module through the dynamic loader from a
 * location the operator can influence, so the operator decides which object the
 * loader maps -- and an attacker-supplied object runs its own code inside the
 * target process before the program ever inspects it.
 *
 * This is a FILESYSTEM + DYNAMIC-LOADER category. Nothing overflows, no pointer
 * is written, no address is ever computed, and there is no shellcode. It is also
 * DISTINCT from benchmark/corpus_envpath/ (env/$PATH hijack): there the consumer
 * is an execve-style lookup of an EXECUTABLE on $PATH; here the consumer is
 * dlopen()/ld.so and the payload is a SHARED OBJECT whose ELF constructor (or
 * exported init symbol) runs.
 *
 * HELD IDENTICAL IN EVERY TARGET OF THIS FAMILY
 * ---------------------------------------------
 *   * the legitimate feature   the program loads an extension module and calls
 *                              the family's documented init symbol
 *                              `supwngo_plugin_init` on it, printing what that
 *                              returns. With the module installed where this
 *                              target documents it, this WORKS NORMALLY -- the
 *                              legitimate module is one shared source for the
 *                              whole family (supwngo_ext.c, SONAME
 *                              libsupwngoext.so.1, installed by
 *                              install_plugins.sh);
 *   * the secret              flag.txt sits BESIDE THE BINARY. Its path is
 *                              resolved ABSOLUTELY at startup from
 *                              /proc/self/exe and the program FAILS CLOSED
 *                              (exits) if that path cannot be stat'd, so no cwd
 *                              trick can quietly switch the guard off -- which
 *                              matters here more than anywhere, because this
 *                              variant's whole mechanism is a changed cwd;
 *   * the working directory    one per slug, /tmp/supwngo_libhj_<NN>, never
 *                              shared with another target;
 *   * the protections          canary + NX + PIE + Full RELRO, all ON, from a
 *                              cflags file whose protection lines are identical
 *                              across the family;
 *   * the win condition        code execution inside the target process. The
 *                              planted object spawns /bin/sh, which is proved
 *                              with a COMPUTED marker (`echo SH$((6*7))OK` ->
 *                              `SH42OK`, which /bin/echo cannot produce) and
 *                              then used to read the flag.txt beside the binary;
 *   * what is NOT here         no system(), no popen(), no execve of a $PATH
 *                              name, no overflow, no format string. The only
 *                              way in is the loader.
 *
 * THE ONE VARIABLE IN THIS FAMILY IS HOW THE LOADER IS POINTED AT THE OBJECT.
 *
 * THIS TARGET'S MECHANISM: a RELATIVE dlopen path, resolved against the CWD.
 * dlopen("./plugins/libsupwngoext.so.1", RTLD_NOW) contains a slash, so the
 * loader does NOT search any library path at all -- it resolves the string
 * relative to the process's current working directory, exactly as open(2) would.
 * The program never chdir()s, so whoever starts it chooses what "." means. Run
 * from its own directory the legitimate module loads; run from a directory the
 * operator prepared, the operator's object loads. This is the anchor variant:
 * the cheapest possible loader influence, needing no environment variable, no
 * RUNPATH and no search order.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Per-slug working directory. Created at startup so an operator always has a
 * documented place to stage things; never shared with another target. */
#define WORKDIR "/tmp/supwngo_libhj_10"
#define SECRET_NAME "flag.txt"

/* THE MECHANISM, in one string: relative, so the CWD decides. */
#define PLUGIN_PATH "./plugins/libsupwngoext.so.1"

/* The family's documented plugin ABI. */
#define PLUGIN_INIT_SYM "supwngo_plugin_init"
typedef const char *(*plugin_init_fn)(void);

static char secret_path[4096];

/* Resolve the secret's ABSOLUTE path from /proc/self/exe and fail closed.
 *
 * Absolute-from-/proc/self/exe rather than relative, and fail-closed rather than
 * fail-soft, for a reason specific to this family: several variants are exploited
 * by starting the program somewhere else entirely, so a relative "flag.txt"
 * would silently refer to a different file (or to nothing) and the corpus would
 * stop measuring what it claims to measure.
 */
static void locate_secret(void)
{
    char exe[4096];
    struct stat st;
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    char *slash;

    if (n <= 0) {
        fprintf(stderr, "fatal: cannot resolve /proc/self/exe\n");
        exit(1);
    }
    exe[n] = 0;
    slash = strrchr(exe, '/');
    if (!slash) {
        fprintf(stderr, "fatal: /proc/self/exe has no directory component\n");
        exit(1);
    }
    *slash = 0;
    snprintf(secret_path, sizeof secret_path, "%s/%s", exe, SECRET_NAME);
    if (stat(secret_path, &st) != 0) {
        fprintf(stderr, "fatal: protected file %s is not present\n", secret_path);
        exit(1);
    }
}

/* THE DEFECT. One dlopen() of a relative path, one dlsym() of the documented
 * init symbol, one call. Every line of this is the legitimate feature; the
 * defect is only that the path's first component is resolved against a cwd the
 * program does not control and never checks. */
static void load_plugin(void)
{
    void *handle;
    plugin_init_fn init;

    handle = dlopen(PLUGIN_PATH, RTLD_NOW);
    if (!handle) {
        printf("plugin: not loaded (%s)\n", dlerror());
        return;
    }
    init = (plugin_init_fn) dlsym(handle, PLUGIN_INIT_SYM);
    if (!init) {
        printf("plugin: %s missing (%s)\n", PLUGIN_INIT_SYM, dlerror());
        return;
    }
    printf("plugin: %s\n", init());
}

int main(void)
{
    char line[256];

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(WORKDIR, 0777);
    printf("supwngo extension host (loader route: cwd-relative dlopen)\n");
    printf("module path: %s\n", PLUGIN_PATH);
    printf("work dir: %s\n", WORKDIR);
    printf("secret guard: ok\n");

    load_plugin();

    /* A minimal command loop, so the process is a service rather than a
     * one-shot and an operator can ask what loaded. Deliberately offers no file
     * access of any kind: the only way to reach the secret is code execution. */
    for (;;) {
        printf("cmd> ");
        fflush(stdout);
        if (!fgets(line, sizeof line, stdin))
            break;
        line[strcspn(line, "\n")] = 0;
        if (!strcmp(line, "quit"))
            break;
        if (!strcmp(line, "status"))
            printf("status: extension host running\n");
        else if (line[0])
            printf("commands: status, quit\n");
    }
    return 0;
}
