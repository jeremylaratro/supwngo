/*
 * libhj_14_plugin_dir_scan
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
 * THIS TARGET'S MECHANISM: a DROP-IN DIRECTORY SCAN. The program opendir()s its
 * documented drop-in directory, and for every entry whose name contains ".so" it
 * dlopen()s that entry and dlsym()s the family's init symbol. The FILENAME IS NOT
 * FIXED -- that is what makes this variant structurally different from libhj_10
 * and libhj_11, where the operator has to overwrite a specific name. Here
 * anything the operator drops in is loaded, in whatever order readdir() returns
 * it, and the program's only filter is a substring test on the name.
 *
 * The drop-in directory is the family's per-slug working directory under /tmp,
 * which is the corpus's documented operator-writable area (real deployments put
 * the same pattern in a group-writable /usr/local prefix or a per-user config
 * directory; the defect is identical and the corpus does not need a privilege
 * asymmetry to express it). When the drop-in directory contains no module the
 * program falls back to the BUNDLED module in its own plugins/ directory, which
 * is the legitimate configuration and the one that must keep working.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WORKDIR "/tmp/supwngo_libhj_14"
#define SECRET_NAME "flag.txt"

/* THE MECHANISM: this directory is SCANNED, and whatever looks like a module is
 * loaded. The drop-in directory is the per-slug working directory itself. */
#define PLUGIN_DROPIN WORKDIR
#define PLUGIN_SONAME "libsupwngoext.so.1"
#define PLUGIN_SUBDIR "plugins"

#define PLUGIN_INIT_SYM "supwngo_plugin_init"
typedef const char *(*plugin_init_fn)(void);

static char secret_path[4096];
static char bindir[4096];

/* Resolve the secret's ABSOLUTE path from /proc/self/exe and fail closed. */
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

static int load_one(const char *path)
{
    void *handle;
    plugin_init_fn init;

    handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        printf("plugin: not loaded (%s)\n", dlerror());
        return 0;
    }
    init = (plugin_init_fn) dlsym(handle, PLUGIN_INIT_SYM);
    if (!init) {
        printf("plugin: %s missing in %s (%s)\n", PLUGIN_INIT_SYM, path, dlerror());
        return 0;
    }
    printf("plugin: %s\n", init());
    return 1;
}

/* THE DEFECT. Every entry whose name merely CONTAINS ".so" is handed to dlopen,
 * with no check on where it came from, who wrote it, or what it is. */
static void load_plugins(void)
{
    char path[4096];
    DIR *dir;
    struct dirent *ent;
    int loaded = 0;

    dir = opendir(PLUGIN_DROPIN);
    if (dir) {
        while ((ent = readdir(dir)) != NULL) {
            if (!strstr(ent->d_name, ".so"))
                continue;
            snprintf(path, sizeof path, "%s/%s", PLUGIN_DROPIN, ent->d_name);
            printf("module path: %s\n", path);
            loaded += load_one(path);
        }
        closedir(dir);
    }
    if (!loaded) {
        /* The legitimate configuration: nothing dropped in, so the bundled
         * module beside the binary is used. */
        snprintf(path, sizeof path, "%s/%s/%s", bindir, PLUGIN_SUBDIR, PLUGIN_SONAME);
        printf("module path: %s\n", path);
        load_one(path);
    }
}

int main(void)
{
    char line[256];

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(WORKDIR, 0777);
    printf("supwngo extension host (loader route: drop-in directory scan)\n");
    printf("drop-in dir: %s\n", PLUGIN_DROPIN);
    printf("secret guard: ok\n");

    load_plugins();

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
