/*
 * libhj_13_runpath_origin
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
 * THIS TARGET'S MECHANISM: a WRITABLE $ORIGIN RPATH ENTRY, and NO dlopen at all.
 * The extension is a real sibling library linked in the ordinary way, so the
 * module is a DT_NEEDED dependency resolved by ld.so at process startup and the
 * init symbol is bound by the linker rather than looked up with dlsym. The image
 * carries
 *
 *      DT_RPATH = $ORIGIN/lib:$ORIGIN/vendor
 *
 * ($ORIGIN is expanded by the loader to the directory the EXECUTABLE lives in,
 * and -Wl,--disable-new-dtags is what makes this a DT_RPATH rather than a
 * DT_RUNPATH, so both dynamic tags are represented in the family.) The
 * legitimate copy of the module is installed in `vendor/`, the SECOND entry.
 * The FIRST entry, `lib/`, is shipped EMPTY -- and it is a directory the operator
 * can write. An empty-but-writable early search-path entry is the whole defect:
 * anything the operator drops into $ORIGIN/lib satisfies the soname first and is
 * mapped, relocated and CONSTRUCTED before main() runs.
 *
 * Two consequences of the NEEDED route that do not apply to the dlopen variants,
 * both derived from the loader's documented behaviour rather than assumed:
 *
 *   * the planted object must actually DEFINE `supwngo_plugin_init`. This image
 *     is linked -z now (Full RELRO), so every relocation is resolved before any
 *     constructor runs; a planted object that omits the symbol makes the loader
 *     abort with "undefined symbol" and nothing of the attacker's code runs;
 *   * there is nothing to race and no call site to reach. The object is
 *     constructed during process startup, so the exploit's code runs BEFORE the
 *     program's first line.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WORKDIR "/tmp/supwngo_libhj_13"
#define SECRET_NAME "flag.txt"

/* The family's documented plugin ABI, here satisfied by the ORDINARY DYNAMIC
 * LINKER: the symbol is provided by the DT_NEEDED sibling libsupwngoext.so.1,
 * found through this image's DT_RPATH. No dlopen, no dlsym, no -ldl. */
extern const char *supwngo_plugin_init(void);

static char secret_path[4096];

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
    snprintf(secret_path, sizeof secret_path, "%s/%s", exe, SECRET_NAME);
    if (stat(secret_path, &st) != 0) {
        fprintf(stderr, "fatal: protected file %s is not present\n", secret_path);
        exit(1);
    }
}

int main(void)
{
    char line[256];

    setvbuf(stdout, NULL, _IOLBF, 0);
    locate_secret();
    mkdir(WORKDIR, 0777);
    printf("supwngo extension host (loader route: DT_RPATH $ORIGIN/lib)\n");
    printf("work dir: %s\n", WORKDIR);
    printf("secret guard: ok\n");

    /* THE DEFECT'S CONSUMER. By the time this line runs the module has already
     * been mapped, relocated and constructed by ld.so -- which is why a planted
     * object does not need this call to reach it at all. */
    printf("plugin: %s\n", supwngo_plugin_init());

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
