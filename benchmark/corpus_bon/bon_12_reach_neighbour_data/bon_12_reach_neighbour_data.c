/* bon_12_reach_neighbour_data -- FLAG{supwngo_bench_bon_12_reach_neighbour_data}
 *
 * Category (HELD CONSTANT across benchmark/corpus_bon):
 *   a strlen()-derived length on a never-NUL-terminated heap buffer, reaching
 *   adjacent chunk metadata.
 *
 * Modelled on HTB "bon-nie-appetit"
 * (tests/htb-targets/a12c7383-817e-4cff-a354-e050da854ad6):
 *   new_order    @0xdde  malloc(size) then @0xe32 read(0, ptr, size)  -- fills
 *                        the chunk EXACTLY, never writes a NUL terminator
 *   edit_order   @0xfe3  strlen(orders[i])  <-- THE DEFECT: the length source
 *                @0x100d read(0, orders[i], strlen_result)
 *   show_order   @0xf1a  printf("... %s ...", ptr)  -- reads past the chunk
 *   delete_order @0x10c5 free() then clears the slot -- so there is no naive UAF
 *
 * THE VARIED AXIS (the ONLY thing that differs between the three positives in
 * this corpus): how far past the allocation the strlen()-derived length
 * reaches.
 *
 *   bon_10   ORDER_SZ 0x18 -> REACH = 1 byte (next chunk's size LSB), ANCHOR
 *   bon_11   ORDER_SZ 0x108 -> REACH = 2 bytes (size LSB + size byte 1)
 *   bon_12 (THIS FILE)  ORDER_SZ 0x18, but fill = ORDER_SZ + 8
 *       FILL_SZ below is one pointer LONGER than usable, so new_order's read()
 *       covers the neighbour's ENTIRE 8-byte `size` field. Filled with non-NUL
 *       bytes, that field no longer terminates strlen(), so the strlen-derived
 *       length runs THROUGH the neighbour's header and into the adjacent in-use
 *       chunk's DATA -- and keeps going while that data is itself non-NUL.
 *       REACH = pointer-width (the whole 8-byte size field) and beyond, i.e. an
 *       unbounded heap overflow rather than an off-by-N.
 *       MEASURED with two 0x18 orders both filled: strlen = 0x3b = 59, i.e. 27
 *       bytes past the fill, and the tail reads
 *           b'BBBBBBBBBBBBBBBBBBBBBBBB!\xfd\x01'
 *       -- 0x18 bytes of the NEIGHBOUR'S OWN DATA, then the top chunk's size.
 *
 *       WHY THE FILL HAD TO CHANGE TO GET HERE (measured, and the reason this
 *       is the third point on the axis rather than a third chunk size):
 *       when the fill ends exactly at `usable`, the first bytes strlen() reads
 *       are the neighbour's 8-byte size field, and NO realizable glibc
 *       chunksize has 8 NUL-free bytes -- bytes 4..7 of any chunk size a brk
 *       heap can hold are zero. So strlen() ALWAYS terminates inside the
 *       neighbour's size field, and 1..3 bytes is the hard ceiling on the reach
 *       for any fill == usable variant. Reaching a neighbour's DATA requires
 *       the size field to be pre-filled, which is what FILL_SZ does. The
 *       enabling 8-byte fill overrun is stated here on purpose: it is the axis
 *       knob, not a hidden second bug.
 *
 * HELD CONSTANT in every file: the menu, the "%s" print, free-then-clear, the
 * index bounds check, the 8 slots, the BAG class, and cflags.
 *
 * THE BAG CLASS (menu option 5) and why it is here:
 *   The ORDER class has a size FIXED per variant, because the reach has to be a
 *   property of the PROGRAM -- if the caller chose the size, the caller would
 *   also choose the reach and the three variants would collapse into one
 *   binary. But a fixed-size-only fixture cannot be driven end to end: there is
 *   no allocation whose size matches a forged chunk size, so an overlapping
 *   chunk can never be reclaimed, and no request is too large for tcache, so
 *   there is no unsorted-bin (main_arena) libc leak. The BAG restores the real
 *   target's arbitrary-size allocation for exactly those two jobs.
 *
 *   The BAG is deliberately NOT a strlen() source: it allocates n + 1 and
 *   writes an explicit NUL at o[i][n], so strlen(bag) == n always and editing a
 *   bag stays inside the chunk. That is what keeps the ORDER class the only
 *   strlen source, and therefore keeps the varied axis the only way in.
 *
 * GLIBC PIN: see ./cflags. This corpus is pinned to the BUILD HOST's glibc
 * (2.35 here), NOT to the target's bundled 2.27.
 *
 * Lab fixture. Deliberately vulnerable. Not for use outside this benchmark.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSLOT 8
#define ORDER_SZ 0x18   /* THE VARIED AXIS */
#define FILL_SZ  (ORDER_SZ + 8) /* THE VARIED AXIS: one pointer past usable */
#define BAG_MAX 0x1000

static char *o[NSLOT];
static size_t sz[NSLOT];

static int pick(void)
{
    int i;
    for (i = 0; i < NSLOT; i++)
        if (!o[i])
            return i;
    return -1;
}

static int slot(void)
{
    int i;
    printf("[*] Number of order: ");
    if (scanf("%d", &i) != 1)
        exit(0);
    if (i < 0 || i >= NSLOT || !o[i])
        return -1;
    return i;
}

int main(void)
{
    int c, i;
    unsigned long n;
    setvbuf(stdout, 0, _IONBF, 0);
    for (;;) {
        printf("> ");
        if (scanf("%d", &c) != 1)
            return 0;
        if (c == 1) {
            if ((i = pick()) < 0)
                continue;
            o[i] = malloc(ORDER_SZ);
            if (!o[i])
                return 1;
            sz[i] = ORDER_SZ;
            printf("[*] What would you like to order: ");
            read(0, o[i], FILL_SZ);         /* fills PAST usable, never NUL-terminates */
            printf("[+] order %d\n", i);
        } else if (c == 2) {
            if ((i = slot()) < 0)
                continue;
            printf("[+] Order[%d] => %s \n", i, o[i]);   /* %s reads past the chunk */
        } else if (c == 3) {
            if ((i = slot()) < 0)
                continue;
            printf("[*] New order: ");
            read(0, o[i], strlen(o[i]));    /* THE DEFECT: strlen-derived length */
        } else if (c == 4) {
            if ((i = slot()) < 0)
                continue;
            free(o[i]);
            o[i] = 0;                       /* free-then-clear: no naive UAF */
            sz[i] = 0;
        } else if (c == 5) {
            if ((i = pick()) < 0)
                continue;
            printf("[*] For how many: ");
            if (scanf("%lu", &n) != 1)
                return 0;
            if (n == 0 || n > BAG_MAX)
                continue;
            o[i] = malloc(n + 1);           /* BAG: one byte of room for a NUL */
            if (!o[i])
                return 1;
            sz[i] = n;
            printf("[*] What would you like to order: ");
            read(0, o[i], n);
            o[i][n] = 0;                    /* BAG is NUL-terminated: not a strlen source */
            printf("[+] bag %d\n", i);
        } else {
            return 0;
        }
    }
}
