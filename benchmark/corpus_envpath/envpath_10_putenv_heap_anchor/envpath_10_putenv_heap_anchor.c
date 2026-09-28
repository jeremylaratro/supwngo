/*
 * envpath_10_putenv_heap_anchor -- FLAG{supwngo_bench_envpath_10_putenv_heap_anchor}
 *
 * Family: benchmark/corpus_envpath/ -- an unbounded forward heap write whose
 * reachable sink lets the program's own later system(<relative path>) call be
 * redirected. Held IDENTICAL across every target in the family:
 *
 *   * the size wrap        Malloc(n) does malloc(n + 8), so n = 2**64 - 8
 *                          wraps to malloc(0) and SUCCEEDS;
 *   * the unsigned bound   readBuffer()'s `i < n` with n a size_t never trips,
 *                          so the write runs forward without limit;
 *   * the relative sink    system("panel") -- resolved through $PATH;
 *   * the plant primitive  the target's own open()/write() pair, 7-character
 *                          name (no '.', no '/'), one line of <= 30 characters,
 *                          and no O_TRUNC;
 *   * the heap geometry    read_option()'s Malloc/Free leaves a 0x20 tcache
 *                          chunk at the bottom of the heap, so the wrapped
 *                          malloc(0) reuses it and the sink chunk sits exactly
 *                          0x20 bytes above the returned pointer.
 *
 * THE ONE VARIABLE IN THIS FAMILY IS WHICH REACHABLE SINK THE OVERFLOW LANDS ON.
 *
 * THIS TARGET'S SINK: a heap-resident environment entry that is ALREADY
 * registered with putenv() when the overflow happens. Overwriting it with
 * "PATH=/tmp:/bin" installs a second PATH binding that sits after the inherited
 * one in the environ array, so the shell the shebang interpreter spawns takes
 * the forged one. This is the anchor: it is the shape measured in the HTB target
 * `sabotage` (tests/htb-targets/a12c7382-edc2-4554-ab36-fe26b48f8fd4).
 *
 * Menu ordering is load-bearing, exactly as in the measured target: option 2
 * must run BEFORE option 1, because option 2 is what puts a heap chunk above
 * the chunk option 1 overflows out of. Option 1 alone walks straight into the
 * top chunk and glibc aborts with "malloc(): corrupted top size".
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The allocator wrapper: malloc(n + 8), stash the length, hand back data + 8. */
static void *Malloc(size_t n)
{
    char *p = (char *)malloc(n + 8);
    if (!p)
        return NULL;
    *(size_t *)p = n;
    return p + 8;
}

static void Free(void *p)
{
    if (p)
        free((char *)p - 8);
}

/* The unbounded forward write: `i < n` with n unsigned never trips. */
static void readBuffer(char *b, size_t n)
{
    for (size_t i = 0; i < n;) {
        read(0, b + i, 1);
        if (!b[i])
            return;
        if (b[i] == '\n') {
            b[i] = 0;
            return;
        }
        i++;
    }
}

static void setup(void)
{
    /* Unbuffered stdio, as in the measured target. Load-bearing for the heap
       layout: a buffered stdin would malloc a 0x1000 FILE buffer between the
       menu reader's freed scratch chunk and the sink chunk. */
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}

static long read_option(void)
{
    /* Malloc/Free of a 0x10 scratch buffer leaves a 0x20 tcache chunk at the
       very bottom of the heap. The size-wrapped malloc(0) later reuses it,
       which is what puts the sink chunk immediately ABOVE the overflowing
       buffer rather than below it. */
    char *buf = (char *)Malloc(0x10);
    long value;

    printf("> ");
    if (!buf || !fgets(buf, 0x10, stdin))
        exit(0);
    value = strtol(buf, NULL, 0);
    Free(buf);
    return value;
}

static void menu(void)
{
    puts("+---+---------------------------+");
    puts("| 1 | Access control panel.     |");
    puts("| 2 | Use quantum destabilizer. |");
    puts("| 3 | Scan the hull.            |");
    puts("| 4 | Intercept comms.          |");
    puts("| 5 | Abort the mission.        |");
    puts("+---+---------------------------+");
}

/* The target's own file-plant primitive. Budgets are fgets() constants and are
   therefore readable straight out of the disassembly:
     name    fgets(name, 8, ...)     -> 7 characters, and '.' / '/' are rejected
     content fgets(content, 0x20, ...) -> 30 characters plus the newline
   open() carries no O_TRUNC, so rewriting a shorter payload leaves the old
   tail behind. */
static void plant_file(void)
{
    char name[8];
    char path[0x20];
    char content[0x20];
    char *nl;
    int fd;

    printf("[*] mount point: ");
    if (!fgets(name, 8, stdin))
        exit(0);
    if (strchr(name, '.') || strchr(name, '/')) {
        puts("[!] intrusion spotted");
        exit(-1);
    }
    nl = strchr(name, '\n');
    if (nl)
        *nl = 0;
    memset(path, 0, sizeof(path));
    strcpy(path, "/tmp/");
    strcat(path, name);
    fd = open(path, O_RDWR | O_CREAT, 0777);
    if (fd < 0) {
        puts("[!] destabilizer failed");
        exit(-1);
    }
    printf("[*] shield: ");
    if (!fgets(content, 0x20, stdin))
        exit(0);
    write(fd, content, strlen(content));
    close(fd);
    puts("[+] shield deployed");
}

static void quantum_destabilizer(void)
{
    /* THE SINK. A heap-resident environment entry, registered with putenv()
       here -- i.e. it is already live in environ by the time the overflow in
       enter_command_control() reaches it. */
    if (getenv("ACCESS") == NULL) {
        char *e = (char *)Malloc(0x18);
        if (!e)
            exit(-1);
        strcpy(e, "ACCESS=DENIED");
        putenv(e);
    }
    plant_file();
}

static void enter_command_control(void)
{
    size_t n;
    char *p;

    puts("Access to the control panel is protected.");
    /* The measured target has an `if (getenv("ACCESS") == NULL) setenv(...)`
       guard here. It is deliberately NOT reproduced: in a variant whose
       preparation step does not itself register an environment entry, that
       setenv() allocates a 14-byte string, which takes the 0x20 tcache chunk
       the family's heap geometry depends on -- the wrapped malloc(0) then comes
       off the top instead and the sink is no longer 0x20 above it. Keeping the
       guard would silently VARY the geometry, which this family holds fixed.
       MEASURED: with the guard present, the variants' buffer landed 0x2d0 above
       the anchor's and the sink was BELOW it. */
    printf("[*] ACCESS code length: ");
    if (scanf("%lu", &n) != 1)
        return;
    p = (char *)Malloc(n);          /* DEFECT: n + 8 wraps -> malloc(0) */
    if (!p) {
        puts("[!] out of memory");
        exit(-1);
    }
    printf("[*] ACCESS code: ");
    readBuffer(p, n);               /* unbounded forward heap write */
    /* Once the sink no longer starts with "ACCESS=", this setenv appends a new
       entry instead of replacing the clobbered one -- so the forged binding
       survives. */
    setenv("ACCESS", p, 1);
    system("panel");                /* relative: resolved through $PATH */
}

int main(void)
{
    setup();
    puts("=== ENEMY SHIP CONSOLE ===");
    for (;;) {
        long opt;

        menu();
        opt = read_option();
        switch (opt) {
        case 1:
            enter_command_control();
            break;
        case 2:
            quantum_destabilizer();
            break;
        case 3:
            puts("[-] hull nominal");
            break;
        case 4:
            puts("[-] no traffic intercepted");
            break;
        case 5:
            puts("[-] mission aborted");
            exit(0);
        default:
            break;
        }
    }
}
