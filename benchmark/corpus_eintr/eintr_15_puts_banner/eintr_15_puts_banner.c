/*
 * Signal-interrupted accumulator underflow -- observable protocol.
 *
 * The category: a fixed-count read loop of the accumulate-until-complete
 * shape
 *
 *     n = 0;
 *     do { n += read(0, buf + n, want - n); } while (want != n);
 *
 * with `n` SIGNED and the signal handler installed WITHOUT SA_RESTART, so
 * every signal delivered inside the blocking read adds -1 to the cursor and
 * walks it backwards into the loop's own control scalars, which
 * -fstack-protector has placed directly below the array.
 *
 * VARIES FROM THE ANCHOR: the handler puts() its message instead of write()ing it,
 * so no trailing NUL arrives; the message contains no '!'; and the prompt
 * is bracketed, which no [\\w@.-]+ prompt pattern matches.
 * Everything else is held identical to eintr_10_alarm_baseline.
 *
 * FLAG{supwngo_bench_eintr_15_puts_banner}
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * Gadget vocabulary, re-supplied on purpose.
 *
 * The measured target was linked against a glibc whose __libc_csu_init ends in
 *     pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
 * and the `41 5f c3` at the end of that tail contains a `5f c3`, i.e. a
 * `pop rdi; ret`. glibc >= 2.34 dropped __libc_csu_init entirely, so a small
 * dynamically-linked binary built today has NO pop-rdi gadget at all -- for a
 * reason that has nothing to do with this bug class.
 *
 * Without this block the corpus would measure the host's glibc version instead
 * of the signal underflow. It is the same accommodation benchmark/corpus/ makes
 * elsewhere by linking a target -static; here the tail is reproduced directly
 * so everything else about the image stays identical to the target's.
 */
__asm__(".text\n"
        ".p2align 4\n"
        "supwngo_csu_tail:\n"
        "  pop %rbx\n"
        "  pop %rbp\n"
        "  pop %r12\n"
        "  pop %r13\n"
        "  pop %r14\n"
        "  pop %r15\n"
        "  ret\n");

#define BUF_LEN 0x1000
#define MAX_WANT 0xfff
#define NVARS 0x40
#define PROMPT "[ancient]$ "

/* puts()d, not write()n: no trailing NUL reaches the pipe, and the text
 * carries no '!' either. Anything that keyed off those two incidental
 * properties of the measured target's banner stops working here. */
#define BANNER "timer expired"

static char *var_names[NVARS];
static char *var_values[NVARS];
static timer_t alarm_timer;

static void on_alarm(int sig)
{
    (void)sig;
    puts(BANNER);
}

static void install_handler(void)
{
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_handler = on_alarm;  /* sa_flags stays 0: no SA_RESTART */
    if (sigaction(SIGALRM, &act, NULL) < 0) {
        perror("sigaction");
        exit(1);
    }
}

static char *lookup(const char *name)
{
    int i;

    for (i = 0; i < NVARS; i++) {
        if (var_names[i] != NULL && strcmp(var_names[i], name) == 0)
            return var_values[i];
    }
    return NULL;
}

static int set_variable(const char *name, const char *value)
{
    int i;

    for (i = 0; i < NVARS; i++) {
        if (var_names[i] == NULL) {
            var_names[i] = strdup(name);
            var_values[i] = strdup(value);
            return (var_names[i] == NULL || var_values[i] == NULL);
        }
    }
    return 1;
}

static int cmd_exit(char *args)
{
    (void)args;
    exit(0);
}

static int cmd_whoami(char *args)
{
    (void)args;
    puts("user");
    return 0;
}

static int cmd_vars(char *args)
{
    int i;

    (void)args;
    for (i = 0; i < NVARS; i++) {
        if (var_names[i] != NULL)
            puts(var_names[i]);
    }
    return 0;
}

/* "echo <$variable/string>" */
static int cmd_echo(char *args)
{
    char *value;

    if (args == NULL) {
        puts("echo <$variable/string>");
        return 1;
    }
    if (args[0] == '$') {
        value = lookup(args + 1);
        if (value == NULL)
            printf("%s is not defined\n", args);
        else
            puts(value);
    } else {
        puts(args);
    }
    return 0;
}

/* "alarm <seconds>" */
static int cmd_alarm(char *args)
{
    struct sigevent sev;
    struct itimerspec its;
    int secs;

    if (args == NULL) {
        puts("alarm <seconds>");
        return 1;
    }
    secs = atoi(args);
    if (secs <= 0)
        return 1;

    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGALRM;
    if (timer_create(CLOCK_REALTIME, &sev, &alarm_timer) < 0) {
        perror("timer_create");
        return 1;
    }

    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = secs;
    if (timer_settime(alarm_timer, 0, &its, NULL) < 0) {
        perror("timer_settime");
        return 1;
    }
    return 0;
}

/* "read <amount of bytes> <variable>" */
static int cmd_read(char *args)
{
    char buf[BUF_LEN];
    char *sp;
    int want;
    int n;

    if (args == NULL) {
        puts("read <amount of bytes> <variable>");
        return 1;
    }
    memset(buf, 0, sizeof(buf));

    sp = strchr(args, ' ');
    if (sp == NULL) {
        puts("read <amount of bytes> <variable>");
        return 1;
    }
    *sp = '\0';
    if (lookup(sp + 1) != NULL) {
        printf("read: variable $%s already exists\n", sp + 1);
        return 1;
    }
    want = atoi(args);
    if (want == 0 || (unsigned int)want > MAX_WANT) {
        puts("read: invalid size");
        return 1;
    }

    n = 0;
    do {
        /* THE DEFECT: read()'s return value is added unconditionally, so an
         * EINTR (-1) walks the cursor backwards into `n` and `want` below. */
        n += read(0, buf + n, want - n);
    } while (want != n);
    getchar();

    if (set_variable(sp + 1, buf))
        puts("read: maximum amount of variables reached");
    return 0;
}

struct command {
    const char *name;
    int (*fn)(char *args);
};

static const struct command commands[] = {
    {"exit", cmd_exit},   {"alarm", cmd_alarm},   {"echo", cmd_echo},
    {"read", cmd_read},   {"whoami", cmd_whoami}, {"vars", cmd_vars},
};

int main(void)
{
    char line[BUF_LEN];
    char *args;
    int n, i, handled;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    install_handler();

    for (;;) {
        printf(PROMPT);
        memset(line, 0, sizeof(line));
        n = read(0, line, sizeof(line) - 1);
        if (n <= 1)
            continue;
        line[n - 1] = '\0';

        args = strchr(line, ' ');
        if (args != NULL) {
            *args++ = '\0';
            while (*args == ' ')
                args++;
        }

        handled = 0;
        for (i = 0; i < (int)(sizeof(commands) / sizeof(commands[0])); i++) {
            if (strcmp(line, commands[i].name) == 0) {
                handled = 1;
                commands[i].fn(args);
                break;
            }
        }
        if (!handled)
            printf("%s: command not found\n", line);
    }
    return 0;
}
