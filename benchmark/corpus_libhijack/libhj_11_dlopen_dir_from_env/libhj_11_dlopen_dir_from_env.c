/*
 * libhj_11_dlopen_dir_from_env
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
 *                              (exits) if that path cannot be stat'd;
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
 * THIS TARGET'S MECHANISM: the module's DIRECTORY comes out of the ENVIRONMENT,
 * read with plain getenv(). The program builds `<dir>/libsupwngoext.so.1` with
 * snprintf and dlopen()s the result, where <dir> is getenv("SUPWNGO_PLUGIN_DIR")
 * when that is set and the binary's own plugins/ directory (resolved absolutely
 * from /proc/self/exe) when it is not. The defect is `getenv` rather than
 * `secure_getenv`, and the total absence of any check on what the named
 * directory contains: an environment variable the operator sets decides which
 * object the loader maps. The path handed to dlopen is ABSOLUTE and contains a
 * slash, so -- unlike libhj_12 -- no library search order is involved at all;
 * the influence is entirely in the string the program built.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WORKDIR "/tmp/supwngo_libhj_11"
#define SECRET_NAME "flag.txt"

/* The environment variable that redirects the module directory. */
#define PLUGIN_DIR_ENV "SUPWNGO_PLUGIN_DIR"
#define PLUGIN_SONAME "libsupwngoext.so.1"
#define PLUGIN_SUBDIR "plugins"

#define PLUGIN_INIT_SYM "supwngo_plugin_init"
typedef const char *(*plugin_init_fn)(void);

static char secret_path[4096];
static char bindir[4096];

/* Resolve the secret's ABSOLUTE path from /proc/self/exe and fail closed. The
 * binary's own directory is kept too, because it is the DEFAULT plugin
 * directory -- the legitimate deployment must not depend on the cwd either. */
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
    snprintf(bindir, sizeof bindir, "%s", exe);
    snprintf(secret_path, sizeof secret_path, "%s/%s", exe, SECRET_NAME);
    if (stat(secret_path, &st) != 0) {
        fprintf(stderr, "fatal: protected file %s is not present\n", secret_path);
        exit(1);
    }
}

/* THE DEFECT. The directory is whatever the environment says, read with plain
 * getenv() and used with no validation whatsoever. */
static void load_plugin(void)
{
    char path[4096];
    const char *dir;
    void *handle;
    plugin_init_fn init;

    dir = getenv(PLUGIN_DIR_ENV);
    if (!dir || !dir[0]) {
        char fallback[4096];
        snprintf(fallback, sizeof fallback, "%s/%s", bindir, PLUGIN_SUBDIR);
        snprintf(path, sizeof path, "%s/%s", fallback, PLUGIN_SONAME);
    } else {
        snprintf(path, sizeof path, "%s/%s", dir, PLUGIN_SONAME);
    }
    printf("module path: %s\n", path);

    handle = dlopen(path, RTLD_NOW);
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
    printf("supwngo extension host (loader route: $%s directory)\n", PLUGIN_DIR_ENV);
    printf("work dir: %s\n", WORKDIR);
    printf("secret guard: ok\n");

    load_plugin();

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
