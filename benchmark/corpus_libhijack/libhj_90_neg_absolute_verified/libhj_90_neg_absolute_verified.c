/*
 * libhj_90_neg_absolute_verified  --  THE FAMILY'S NEGATIVE CONTROL
 *
 * Family: benchmark/corpus_libhijack/ -- UNTRUSTED LIBRARY SEARCH PATH
 * (CWE-426 / CWE-427). Every other target in this family lets the operator
 * influence WHICH object the dynamic loader maps. This one does not, and it is
 * repaired TWO INDEPENDENT WAYS so that it is not one edit away from being a
 * positive. It is still a genuinely working program: it loads its legitimate
 * extension module and calls that module's documented init symbol, so a DECLINE
 * from an executor is a decline and not a crash.
 *
 * HELD IDENTICAL WITH THE REST OF THE FAMILY
 * ------------------------------------------
 *   * the legitimate feature   an extension module is loaded through the dynamic
 *                              loader and a documented init symbol is dlsym'd and
 *                              called, and its result is printed;
 *   * the secret              flag.txt sits BESIDE THE BINARY, its path resolved
 *                              ABSOLUTELY at startup from /proc/self/exe with a
 *                              FAIL-CLOSED stat;
 *   * the working directory    /tmp/supwngo_libhj_90, per-slug, never shared;
 *   * the protections          canary + NX + PIE + Full RELRO, all ON, from a
 *                              cflags file whose protection lines are identical
 *                              across the family;
 *   * the command loop         identical: status / quit, and no file access of
 *                              any kind.
 *
 * REPAIR 1 -- NO CHANNEL EXISTS THAT COULD POINT THE LOADER SOMEWHERE ELSE.
 * Each of the five mechanisms the positives use is closed, by construction:
 *
 *   vs libhj_10 (cwd-relative dlopen)   the module path is a compile-time
 *       ABSOLUTE string under a ROOT-OWNED directory. It has a leading '/', so
 *       the cwd is not consulted, and the operator cannot write that directory.
 *   vs libhj_11 (directory from getenv) NO environment variable reaches any path.
 *       The one environment read that remains is a verbosity flag, and it uses
 *       secure_getenv() rather than getenv().
 *   vs libhj_12 (bare soname search)    the path contains slashes, so ld.so does
 *       no search at all: LD_LIBRARY_PATH, ld.so.cache and the default
 *       directories are never consulted for it.
 *   vs libhj_13 (writable $ORIGIN RPATH) this image has NO DT_RUNPATH and NO
 *       DT_RPATH -- not an $ORIGIN one, not any one. (Verify:
 *       `readelf -d libhj_90_neg_absolute_verified | grep -E 'RPATH|RUNPATH'`
 *       prints nothing.) There is also no DT_NEEDED entry that is not a system
 *       library.
 *   vs libhj_14 (drop-in directory scan) nothing is enumerated. There is no
 *       opendir/readdir/scandir in the image; exactly one module is ever loaded
 *       and its name is a constant.
 *
 * REPAIR 2 -- THE FILE THAT IS ACTUALLY LOADED IS IDENTITY-CHECKED FIRST.
 * Even granting an attacker who somehow replaced the file at that path, the
 * program open()s the path ONCE, answers the whole policy with fstat() on THE
 * DESCRIPTOR IT WILL LOAD FROM (a plain file, exactly one link, owned by the
 * expected uid), and then loads it through that same descriptor via
 * /proc/self/fd/<n> rather than re-resolving the name. So the bytes mapped are
 * provably the bytes checked -- there is no second path walk for a swap to land
 * in, which is also why this control cannot be attacked as a TOCTOU race. Either
 * repair ALONE defeats all five mechanisms; both are present.
 *
 * THE CONTROL'S HONEST LIMIT, STATED RATHER THAN ROUNDED OFF
 * ---------------------------------------------------------
 * "A directory the attacker cannot write" is only expressible in a SAME-UID
 * corpus by pointing at a real system directory, so this control's legitimate
 * extension module is a vendor system object -- /lib/x86_64-linux-gnu/libz.so.1,
 * owned by root in a root-owned directory -- and its documented init symbol is
 * that module's own zlibVersion(). That is the ONE respect in which this target
 * differs from the family beyond the absence of the bug, and it is a consequence
 * of the "cannot write" requirement rather than a free choice: the family's own
 * extension cannot be installed under a root-owned prefix without root. A real
 * deployment would ship the family extension under /usr/lib and this control
 * would be byte-for-byte the same program with a different constant.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WORKDIR "/tmp/supwngo_libhj_90"
#define SECRET_NAME "flag.txt"

/* The extension module: an ABSOLUTE path under a ROOT-OWNED directory. No
 * environment variable, no search path and no directory scan can move it. */
#define PLUGIN_PATH "/lib/x86_64-linux-gnu/libz.so.1"

/* The documented init symbol of that module. See "THE CONTROL'S HONEST LIMIT". */
#define PLUGIN_INIT_SYM "zlibVersion"
typedef const char *(*plugin_init_fn)(void);

/* The uid the module is required to be owned by. A vendor system object is
 * root-owned; anything else is refused. */
#define PLUGIN_EXPECTED_UID 0

/* The only environment read left in the image, and it is a verbosity flag that
 * never touches a path. secure_getenv() rather than getenv() on purpose: under a
 * privilege change it returns NULL, so even this cannot be used to influence the
 * program from a lower-privileged context. */
#define VERBOSE_ENV "SUPWNGO_PLUGIN_VERBOSE"

static char secret_path[4096];

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

/* REPAIR 2. One resolution of the name, then the whole policy answered against
 * the descriptor, then a load THROUGH that descriptor. */
static void load_plugin(void)
{
    char fdpath[64];
    struct stat st;
    void *handle;
    plugin_init_fn init;
    int fd;

    fd = open(PLUGIN_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("plugin: refused (cannot open %s)\n", PLUGIN_PATH);
        return;
    }
    if (fstat(fd, &st) != 0) {
        printf("plugin: refused (cannot fstat the descriptor)\n");
        close(fd);
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        printf("plugin: refused (not a plain file)\n");
        close(fd);
        return;
    }
    if (st.st_nlink != 1) {
        printf("plugin: refused (extra links)\n");
        close(fd);
        return;
    }
    if (st.st_uid != PLUGIN_EXPECTED_UID) {
        printf("plugin: refused (owner uid %u, expected %u)\n",
               (unsigned) st.st_uid, (unsigned) PLUGIN_EXPECTED_UID);
        close(fd);
        return;
    }

    /* Load the VERIFIED DESCRIPTOR, not the name. /proc/self/fd/<n> refers to
     * the open file this program is holding, so the object mapped is the object
     * fstat() just approved. */
    snprintf(fdpath, sizeof fdpath, "/proc/self/fd/%d", fd);
    handle = dlopen(fdpath, RTLD_NOW);
    if (!handle) {
        printf("plugin: not loaded (%s)\n", dlerror());
        close(fd);
        return;
    }
    close(fd);
    init = (plugin_init_fn) dlsym(handle, PLUGIN_INIT_SYM);
    if (!init) {
        printf("plugin: %s missing (%s)\n", PLUGIN_INIT_SYM, dlerror());
        return;
    }
    printf("plugin: verified vendor module %s, init %s() -> %s\n",
           PLUGIN_PATH, PLUGIN_INIT_SYM, init());
}

int main(void)
{
    char line[256];
    const char *verbose = secure_getenv(VERBOSE_ENV);

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(WORKDIR, 0777);
    printf("supwngo extension host (loader route: none -- verified absolute path)\n");
    printf("module path: %s\n", PLUGIN_PATH);
    printf("work dir: %s\n", WORKDIR);
    printf("secret guard: ok\n");
    if (verbose && verbose[0])
        printf("verbose: on\n");

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
