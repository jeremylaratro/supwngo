/*
 * objptr_libc corpus -- a record manager finished from LIBC.
 *
 * THE CATEGORY: each record carries a `print` function pointer the program
 * CALLS indirectly, and a `note` pointer it passes as that call's argument. An
 * unsigned size computation lets the note copy outrun its allocation, so the
 * copy runs forward out of a recycled block into the next live record and
 * rewrites both members. The image contains NO win function and NO system@plt,
 * so the destination must be resolved in libc: leak the arena, use the
 * (note, print) pair as an arbitrary read to recover the image base, read the
 * R_X86_64_COPY slot the loader filled with a libc address, then point `print`
 * at libc's `system` and `note` at a string of our choosing.
 *
 * VARIES FROM THE ANCHOR: the size arithmetic that wraps is an ALIGN-UP, not `sz + 1`, so the wrapping input is one of seven values rather than exactly 2**64-1.
 *
 * ROLE: positive
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NREC     8
#define ARENA_SZ 0x800
#define NBLK     32
#define COPYCAP  0x100
#define NAME_SZ  16
#define SUR_SZ   16

typedef struct Rec {
    char  name[NAME_SZ];
    char  surname[SUR_SZ];
    char *note;
    unsigned long age;
    void (*print)(char *);
} Rec;

static Rec *records[NREC];

/* Allocator with OUT-OF-BAND metadata, a bump `top`, and a first-fit free list.
 * Modelled on the measured target's: a zero-size request is satisfied from an
 * existing free block rather than from `top`, which is what makes a freed block
 * recyclable and lets a copy start immediately below a live record. */
struct blk { char *addr; size_t size; int used; };
static char arena[ARENA_SZ];
static struct blk blocks[NBLK];
static size_t top;

static void *xalloc(size_t n)
{
    size_t i;

    n = (n + 7) & ~(size_t)7;
    for (i = 0; i < NBLK; i++)
        if (blocks[i].addr && !blocks[i].used && blocks[i].size >= n) {
            blocks[i].used = 1;
            return blocks[i].addr;
        }
    if (top + n > ARENA_SZ)
        return NULL;
    for (i = 0; i < NBLK; i++)
        if (!blocks[i].addr) {
            blocks[i].addr = arena + top;
            blocks[i].size = n;
            blocks[i].used = 1;
            top += n;
            return blocks[i].addr;
        }
    return NULL;
}

static void xfree(void *p)
{
    size_t i;

    for (i = 0; i < NBLK; i++)
        if (blocks[i].addr == (char *)p)
            blocks[i].used = 0;
}

static void print_note(char *s)
{
    printf("note: [%s]\n", s);
    
}

/* The (dest, size) reader. Writes at most size-1 bytes and NEVER a terminator:
 * that `size - 1` bound is the fact the analysis has to read, because it is what
 * decides whether a member is left unterminated. */
static int read_field(char *dst, size_t n)
{
    size_t i = 0;
    char c;

    if (!dst || !n)
        return 0;
    while (read(0, &c, 1) == 1 && i < n - 1) {
        if (c == '\n')
            return 1;
        dst[i++] = c;
    }
    return 1;
}

static unsigned long read_number(void)
{
    char buf[32];

    memset(buf, 0, sizeof(buf));
    if (scanf("%31s", buf) != 1)
        exit(0);
    return strtoul(buf, NULL, 10);
}

void add_record(void)
{
    unsigned long i, sz, len;
    Rec *r;

    for (i = 0; i < NREC; i++) {
        if (records[i])
            continue;
        records[i] = (Rec *)xalloc(sizeof(Rec));
        if (!records[i]) {
            printf("alloc failed!\n");
            
            exit(0);
        }
        r = records[i];
        r->print = print_note;
        printf("Name: ");
        
        read_field(r->name, NAME_SZ);
        printf("Surname: ");
        
        read_field(r->surname, SUR_SZ);
        printf("Age: ");
        
        r->age = read_number();
        printf("Record Note size: ");
        
        sz = read_number();
        if (sz) {
            r->note = (char *)xalloc((sz + 7) & ~7UL);
            if (!r->note) {
                printf("alloc failed!\n");
                
                exit(0);
            }
            printf("Note: ");
            
            len = sz > COPYCAP ? COPYCAP : sz + 1;
            read_field(r->note, len);
        }
        printf("Record %lu added!\n\n", i + 1);
        
        return;
    }
    printf("MAX RECORDS REACHED!\n");
    
}

void mod_record(void)
{
    unsigned long id;
    Rec *r;

    printf("Record ID: ");
    
    id = read_number();
    if (id == 0 || id > NREC)
        return;
    r = records[id - 1];
    if (!r) {
        printf("Record %lu does not exist!\n\n", id);
        
        return;
    }
    printf("Name: ");
    
    read_field(r->name, NAME_SZ);
    printf("Surname: ");
    
    read_field(r->surname, SUR_SZ + 1);
    printf("Age: ");
    
    r->age = read_number();
}

void show_record(void)
{
    unsigned long id;
    Rec *r;

    printf("Record ID: ");
    
    id = read_number();
    if (id == 0 || id > NREC)
        return;
    r = records[id - 1];
    if (!r) {
        printf("Record %lu does not exist!\n\n", id);
        
        return;
    }
    printf("----------------------\n");
    printf("Record %lu\n", id);
    printf("Name: %s\n", r->name);
    printf("Surname: %s\n", r->surname);
    printf("Age: %lu\n", r->age);
    r->print(r->note);
    printf("-----------------------\n");
    
}

void del_record(void)
{
    unsigned long id;
    Rec *r;

    printf("Record ID: ");
    
    id = read_number();
    if (id == 0 || id > NREC)
        return;
    r = records[id - 1];
    if (!r) {
        printf("Record %lu does not exist!\n\n", id);
        
        return;
    }
    xfree(r->note);
    xfree(r);
    records[id - 1] = NULL;
    printf("Record %lu deleted!\n\n", id);
    
}

static void menu(void)
{
    printf("1 - Add Record\n");
    printf("2 - Modify Record\n");
    printf("3 - Show Record\n");
    printf("4 - Delete Record\n");
    printf("5 - Exit\n");
    printf("Choice: ");
    
}

int main(void)
{
    unsigned long c;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("*** record editor ***\n");
    
    while (1) {
        menu();
        c = read_number();
        switch (c) {
        case 1: add_record(); break;
        case 2: mod_record(); break;
        case 3: show_record(); break;
        case 4: del_record(); break;
        case 5: puts("bye bye!"); return 0;
        default: break;
        }
    }
    return 0;
}
