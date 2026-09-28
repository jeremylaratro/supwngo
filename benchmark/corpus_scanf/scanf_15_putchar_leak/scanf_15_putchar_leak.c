/*
 * Unbounded scanf/strtoull scalar-and-buffer overwrite on PIE + canary +
 * Full RELRO -- VARIANT.
 *
 * VARIES, versus scanf_10_fnptr_struct: WHERE THE LEAK COMES FROM. The overwrite
 * is the anchor's, unchanged -- an unbounded `%s` into `struct record`'s
 * `name[]`, landing on the trailing `show` pointer. What changes is the oracle
 * that makes PIE tractable: instead of `printf("%llu", slots[idx])` over an
 * array of qwords, this target has a BYTE oracle -- `putchar(slots[idx])` over an
 * array of bytes.
 *
 * WHY THAT IS A DIFFERENT CAPABILITY
 * The anchor's leak hands over a whole 64-bit value in one exchange, as decimal
 * text. This one hands over ONE RAW BYTE per exchange, so a code address costs
 * six round trips and has to be reassembled little-endian; the scale of the
 * subscript is 1 rather than 8, so every index the anchor used is wrong by a
 * factor of eight; and the output is not text at all -- a leaked byte may be any
 * value including 0x00 and 0x0a, so anything that reads the oracle's answer as a
 * line, or parses it as a number, gets nothing. An implementation that hardcodes
 * "send an index, scrape the integer it prints" fails here while the bug it is
 * meant to exploit is entirely unchanged.
 *
 * FLAG{supwngo_bench_scanf_15_putchar_leak}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_LEN 32
#define NBYTE 64

struct record {
    char name[NAME_LEN];
    void (*show)(const char *);
};

void spawn_admin_shell(void)
{
    system("/bin/sh");
}

static void show_plain(const char *name)
{
    printf("record: %s\n", name);
}

static unsigned long long get_number(void)
{
    char line[32];

    memset(line, 0, sizeof(line));
    if (scanf("%s", line) != 1)
        exit(0);
    return strtoull(line, NULL, 10);
}

/* The leak: one raw byte at an unchecked subscript. Byte-granular, so the
 * canary and the saved return address each take eight exchanges. */
static void dump_byte(void)
{
    unsigned char slots[NBYTE];
    unsigned long long idx;

    memset(slots, 0, sizeof(slots));
    printf("byte: ");
    idx = get_number();
    putchar(slots[idx]);
    putchar('\n');
}

static void edit_record(void)
{
    struct record r;

    memset(&r, 0, sizeof(r));
    r.show = show_plain;
    printf("name: ");
    if (scanf("%s", r.name) != 1)
        exit(0);
    r.show(r.name);
}

int main(void)
{
    unsigned long long choice;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    puts("*** record editor ***");
    for (;;) {
        puts("1 - edit record");
        puts("2 - dump byte");
        puts("3 - exit");
        printf("choice: ");
        choice = get_number();
        if (choice == 1)
            edit_record();
        else if (choice == 2)
            dump_byte();
        else if (choice == 3)
            break;
        else
            puts("?");
    }
    puts("bye");
    return 0;
}
