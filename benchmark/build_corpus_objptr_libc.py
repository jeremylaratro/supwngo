#!/usr/bin/env python3
"""Emit and build benchmark/corpus_objptr_libc/ -- the LIBC-FINISH family.

WHAT THIS FAMILY MEASURES

One solve capability: a menu-driven record manager whose records carry a
function pointer the program later CALLS, where the image itself contains NO
destination for that pointer -- no win function, no `system@plt` -- so the
destination has to be resolved in libc from a leak. That is the shape of the HTB
target `auth-or-out`, and the capability needs six things at once:

  1. a decodable menu (jump table, or a compare chain whose cases are CALLS);
  2. member offsets that are object-relative through a frame slot;
  3. a create operation that both allocates the record and allocates the buffer
     whose copy can outrun it;
  4. a delete operation, so a freed block below a live record exists at all;
  5. the arena offset of that recycled block relative to the victim record;
  6. a libc address the image already carries (an R_X86_64_COPY slot).

Each positive varies ONE of the particulars an implementation shaped around a
single target would have baked in. Each control removes ONE prerequisite, so its
refusal is attributable to that prerequisite and not to different hardening.

PROTECTIONS are byte-identical across every target in the family (see cflags):
PIE is inherent to the category -- a target whose image base is known needs no
leak and therefore does not measure the capability.

NO FLAG IS COMPILED IN. These targets never open a file; they are scored on
SHELL_ACCESS only, so there is nothing for an exploit to echo instead of
exploiting.

Usage:
    python3 benchmark/build_corpus_objptr_libc.py            # write + build all
    python3 benchmark/build_corpus_objptr_libc.py <slug>     # just one
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CORPUS = HERE / "corpus_objptr_libc"

CFLAGS = """\
# Protections for the objptr_libc family. Byte-identical across every target,
# positives and controls alike, so the only thing that varies between them is
# the particular each one's header names.
#
# -fno-stack-protector  the hijack lands on a `call *<reg>` in the middle of a
#                       function, so no epilogue canary check is ever reached;
#                       disabling it keeps the canary from being blamed for a
#                       failure it has nothing to do with.
# -pie -fPIE            INHERENT to this category, not an axis. With a known
#                       image base the destination could be written without any
#                       leak, and the capability under test is precisely the
#                       leak-then-resolve chain.
# -O0                   the `print` member must be RELOADED from memory at the
#                       call site; at -O1+ it can be kept in a register and the
#                       category disappears.
-fno-stack-protector
-pie
-fPIE
-O0
"""

TEMPLATE = r'''/*
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
 * VARIES FROM THE ANCHOR: __VARIES__
 *
 * ROLE: __ROLE__
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NREC     8
#define ARENA_SZ 0x800
#define NBLK     32
#define COPYCAP  0x100
#define NAME_SZ  __NAME_SZ__
__SUR_DEFINE__

typedef struct Rec {
    char  name[NAME_SZ];
__SUR_MEMBER__
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
    __FLUSH__
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
            __FLUSH__
            exit(0);
        }
        r = records[i];
        r->print = print_note;
        printf("Name: ");
        __FLUSH__
        read_field(r->name, NAME_SZ);
__CREATE_SUR_READ__
        printf("Age: ");
        __FLUSH__
        r->age = read_number();
        printf("Record Note size: ");
        __FLUSH__
        sz = read_number();
        if (sz) {
            r->note = (char *)xalloc(__WRAP_EXPR__);
            if (!r->note) {
                printf("alloc failed!\n");
                __FLUSH__
                exit(0);
            }
            printf("Note: ");
            __FLUSH__
            len = sz > COPYCAP ? COPYCAP : sz + 1;
            read_field(r->note, len);
        }
        printf("Record %lu added!\n\n", i + 1);
        __FLUSH__
        return;
    }
    printf("MAX RECORDS REACHED!\n");
    __FLUSH__
}

void mod_record(void)
{
    unsigned long id;
    Rec *r;

    printf("Record ID: ");
    __FLUSH__
    id = read_number();
    if (id == 0 || id > NREC)
        return;
    r = records[id - 1];
    if (!r) {
        printf("Record %lu does not exist!\n\n", id);
        __FLUSH__
        return;
    }
__MOD_BODY__
    printf("Age: ");
    __FLUSH__
    r->age = read_number();
}

void show_record(void)
{
    unsigned long id;
    Rec *r;

    printf("Record ID: ");
    __FLUSH__
    id = read_number();
    if (id == 0 || id > NREC)
        return;
    r = records[id - 1];
    if (!r) {
        printf("Record %lu does not exist!\n\n", id);
        __FLUSH__
        return;
    }
    printf("----------------------\n");
    printf("Record %lu\n", id);
    printf("Name: %s\n", r->name);
__SUR_PRINT__
    printf("Age: %lu\n", r->age);
__CALL_SITE__
    printf("-----------------------\n");
    __FLUSH__
}
__DEL_RECORD__
static void menu(void)
{
    printf("1 - Add Record\n");
    printf("2 - Modify Record\n");
    printf("3 - Show Record\n");
    printf("4 - Delete Record\n");
    printf("5 - Exit\n");
    printf("Choice: ");
    __FLUSH__
}

int main(void)
{
    unsigned long c;

__INIT__
    printf("*** record editor ***\n");
    __FLUSH__
    while (1) {
        menu();
        c = read_number();
__DISPATCH__
    }
    return 0;
}
'''

DEL_RECORD = r'''
void del_record(void)
{
    unsigned long id;
    Rec *r;

    printf("Record ID: ");
    __FLUSH__
    id = read_number();
    if (id == 0 || id > NREC)
        return;
    r = records[id - 1];
    if (!r) {
        printf("Record %lu does not exist!\n\n", id);
        __FLUSH__
        return;
    }
    xfree(r->note);
    xfree(r);
    records[id - 1] = NULL;
    printf("Record %lu deleted!\n\n", id);
    __FLUSH__
}
'''

SWITCH_DISPATCH = """\
        switch (c) {
        case 1: add_record(); break;
        case 2: mod_record(); break;
        case 3: show_record(); break;
        case 4: __DEL_CALL__ break;
        case 5: puts("bye bye!"); return 0;
        default: break;
        }"""

IFCHAIN_DISPATCH = """\
        if (c == 1)
            add_record();
        else if (c == 2)
            mod_record();
        else if (c == 3)
            show_record();
        else if (c == 4)
            __DEL_CALL__
        else if (c == 5) {
            puts("bye bye!");
            return 0;
        }"""

FRAME_CALL = "    r->print(r->note);"
TABLE_CALL = "    records[id - 1]->print(records[id - 1]->note);"


def variant(**kw) -> dict:
    base = dict(
        name_sz=16, sur_sz=16, dispatch="switch", call="frame",
        wrap="sz + 1", leak="surname", has_delete=True, libc_slot=True,
        role="positive",
    )
    base.update(kw)
    return base


TARGETS = {
    "reclibc_30_anchor_jumptable": variant(
        varies="nothing -- this is the anchor. A jump-table menu whose cases CALL "
               "the operations, a call site based on a frame slot, and `xalloc(sz + 1)`."),
    "reclibc_31_ifchain_menu": variant(
        dispatch="ifchain",
        varies="the menu dispatches through an if/else COMPARE CHAIN instead of a "
               "jump table (and gcc compares against a stack slot, not a register)."),
    "reclibc_32_table_call_site": variant(
        call="table",
        varies="the indirect call loads the record pointer STRAIGHT OUT of the "
               "object table at the call site, with no frame slot in between."),
    "reclibc_33_wide_members": variant(
        name_sz=24, sur_sz=24,
        varies="the members are wider, so every offset moves: note at 0x30, age at "
               "0x38, print at 0x40, record 0x48 bytes."),
    "reclibc_34_align_wrap": variant(
        wrap="(sz + 7) & ~7UL",
        varies="the size arithmetic that wraps is an ALIGN-UP, not `sz + 1`, so the "
               "wrapping input is one of seven values rather than exactly 2**64-1."),
    "reclibc_35_leak_first_member": variant(
        sur_sz=0, leak="name",
        varies="there is no second character member: the unterminated array is "
               "`name` at offset 0, and the note pointer follows it directly."),
    "reclibc_90_neg_bounded_leak": variant(
        role="control", leak="bounded",
        varies="the modify operation reads sizeof(surname) rather than "
               "sizeof(surname)+1, so the array always keeps room for a NUL and "
               "nothing after it is ever printed. Everything else is the anchor."),
    "reclibc_91_neg_no_libc_slot": variant(
        role="control", libc_slot=False,
        varies="the image never names a libc data object, so it carries no "
               "R_X86_64_COPY relocation and holds no libc address of its own. "
               "Unbuffered output comes from fflush(NULL), which names no stream."),
    "reclibc_92_neg_no_delete": variant(
        role="control", has_delete=False,
        varies="there is no delete operation, so no block is ever freed and the "
               "recycled block this chain copies out of cannot be created."),
}


def render(slug: str, spec: dict) -> str:
    flush = "" if spec["libc_slot"] else "fflush(NULL);"
    init = ("    setvbuf(stdin, NULL, _IONBF, 0);\n"
            "    setvbuf(stdout, NULL, _IONBF, 0);") if spec["libc_slot"] else \
           "    /* no stream named on purpose: see this file's header */"
    has_sur = spec["sur_sz"] > 0
    if spec["leak"] == "name":
        mod_body = ('    printf("Name: ");\n    __FLUSH__\n'
                    "    read_field(r->name, NAME_SZ + 1);")
    elif spec["leak"] == "bounded":
        mod_body = ('    printf("Name: ");\n    __FLUSH__\n'
                    "    read_field(r->name, NAME_SZ);\n"
                    '    printf("Surname: ");\n    __FLUSH__\n'
                    "    read_field(r->surname, SUR_SZ);")
    else:
        mod_body = ('    printf("Name: ");\n    __FLUSH__\n'
                    "    read_field(r->name, NAME_SZ);\n"
                    '    printf("Surname: ");\n    __FLUSH__\n'
                    "    read_field(r->surname, SUR_SZ + 1);")
    dispatch = SWITCH_DISPATCH if spec["dispatch"] == "switch" else IFCHAIN_DISPATCH
    dispatch = dispatch.replace(
        "__DEL_CALL__", "del_record();" if spec["has_delete"] else "break;")
    if not spec["has_delete"]:
        dispatch = dispatch.replace("case 4: break; break;", "case 4: break;")
        dispatch = dispatch.replace("        else if (c == 4)\n            break;\n",
                                    "")
    out = TEMPLATE
    out = out.replace("__VARIES__", spec["varies"])
    out = out.replace("__ROLE__", spec["role"])
    out = out.replace("__NAME_SZ__", str(spec["name_sz"]))
    out = out.replace("__SUR_DEFINE__",
                      "#define SUR_SZ   %d" % spec["sur_sz"] if has_sur else "")
    out = out.replace("__SUR_MEMBER__",
                      "    char  surname[SUR_SZ];" if has_sur else "")
    out = out.replace("__CREATE_SUR_READ__",
                      ('        printf("Surname: ");\n        __FLUSH__\n'
                       "        read_field(r->surname, SUR_SZ);") if has_sur else "")
    out = out.replace("__SUR_PRINT__",
                      '    printf("Surname: %s\\n", r->surname);' if has_sur else "")
    out = out.replace("__MOD_BODY__", mod_body)
    out = out.replace("__WRAP_EXPR__", spec["wrap"])
    out = out.replace("__CALL_SITE__",
                      FRAME_CALL if spec["call"] == "frame" else TABLE_CALL)
    out = out.replace("__DEL_RECORD__", DEL_RECORD if spec["has_delete"] else "")
    out = out.replace("__DISPATCH__", dispatch)
    out = out.replace("__INIT__", init)
    out = out.replace("__FLUSH__", flush)
    # Collapse the blank lines left where an optional block was removed.
    while "\n\n\n\n" in out:
        out = out.replace("\n\n\n\n", "\n\n\n")
    return out


def main() -> int:
    wanted = sys.argv[1:] or sorted(TARGETS)
    CORPUS.mkdir(parents=True, exist_ok=True)
    failed = []
    for slug in wanted:
        spec = TARGETS[slug]
        d = CORPUS / slug
        d.mkdir(exist_ok=True)
        (d / (slug + ".c")).write_text(render(slug, spec))
        (d / "cflags").write_text(CFLAGS)
        (d / "flag.txt").write_text(
            "no flag is compiled into this target; it is scored on SHELL_ACCESS\n")
        cmd = ["gcc", "-m64", "-D_FORTIFY_SOURCE=0", "-Wno-format-security",
               "-Wno-unused-result", "-g",
               "-fno-stack-protector", "-pie", "-fPIE", "-O0",
               "-o", str(d / slug), str(d / (slug + ".c"))]
        proc = subprocess.run(cmd, capture_output=True)
        if proc.returncode != 0:
            failed.append(slug)
            print("BUILD FAILED %s\n%s" % (slug, proc.stderr.decode()[:2000]))
        else:
            print("built %-34s %s" % (slug, spec["role"]))
    if failed:
        print("failed: %s" % failed)
        return 1
    print("\n%d targets in %s" % (len(wanted), CORPUS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
