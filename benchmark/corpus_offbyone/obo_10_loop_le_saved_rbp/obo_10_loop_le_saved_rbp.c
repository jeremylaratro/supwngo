/* obo_10_loop_le_saved_rbp -- FLAG{supwngo_bench_obo_10_loop_le_saved_rbp}
 *
 * Category (HELD CONSTANT across benchmark/corpus_offbyone):
 *   CWE-193 (off-by-one) / CWE-787 (out-of-bounds write) -- a fill whose bound
 *   is N writes at index N. Exactly ONE byte lands outside the region, and the
 *   whole family is about what that single byte is allowed to be adjacent to.
 *
 * THE VARIED AXIS (the ONLY thing that differs between the positives):
 *   THE MECHANISM THAT PRODUCES THE EXTRA BYTE, and consequently which frame
 *   slot it lands on.
 *
 *     obo_10 (THIS FILE)  a `for (i = 0; i <= n; i++)` read loop. The extra
 *                         iteration is ATTACKER-FED, so the extra byte is
 *                         whatever the client sends as byte N+1 -- here 0x00,
 *                         onto the low byte of the SAVED RBP.
 *     obo_11              a strcpy-shaped terminator: `dst[len] = '\0'` with
 *                         `len` clamped to `cap` instead of `cap - 1`. Same
 *                         landing site, but the byte is FORCED to NUL -- the
 *                         attacker does not choose it.
 *     obo_12              the extra byte lands on an adjacent LENGTH GUARD,
 *                         which then authorises a second, much larger write.
 *     obo_13              the extra byte lands on the low byte of an adjacent
 *                         SAVED POINTER, which is then used as a write
 *                         destination.
 *     obo_14              same pivot as obo_10/obo_11, but the mechanism is
 *                         snprintf's RETURN VALUE clamped to `cap`, and the
 *                         frame the pivot lands in belongs to the CALLER, not
 *                         to the function that was overflowed.
 *     obo_90              NEGATIVE CONTROL: this file with `i < n`.
 *
 * THE PRIMITIVE, AND WHY ONE BYTE IS ENOUGH
 * -----------------------------------------
 * `buf` is the only local of `do_edit()`, so at -O0 it ends exactly at
 * `-0x0(%rbp)`: `buf[BUF_SZ]` IS the low byte of the saved RBP that `do_edit`
 * pushed on entry, and that saved value is `handle()`'s frame pointer, H.
 * Writing 0x00 there truncates H to `H & ~0xff`, i.e. moves it DOWN by
 * `H & 0xff` bytes -- somewhere between 0 and 240, because rbp is always
 * 16-aligned at -O0.
 *
 * `do_edit` then returns normally (nothing it returns through was damaged --
 * its own saved RBP is the thing that changed, and `leave` merely loads it).
 * `handle()` is now running with a frame pointer that points INTO `do_edit`'s
 * dead frame, i.e. into `buf`. Its own epilogue does the work:
 *
 *     leave      ->  rsp = H & ~0xff ; rbp = *(H & ~0xff)
 *     ret        ->  rip = *((H & ~0xff) + 8)
 *
 * so the next instruction executed is whatever 8-byte word the attacker left at
 * `(H & ~0xff) + 8` -- inside `buf`. No leak, no canary bypass, no GOT write.
 *
 * WHY THE EXPLOIT IS PROBABILISTIC, AND WHAT THE CEILING IS
 * ---------------------------------------------------------
 * `H & 0xff` is not knowable from outside: Linux randomises the initial stack
 * pointer by `get_random_int() % 8192` rounded down to 16, so the low byte of
 * every frame pointer is a fresh multiple of 16 per exec. The landing address
 * (H & ~0xff) + 8 is therefore uniform over 16 candidates, and two of them are
 * losses no payload can fix:
 *
 *   * `H & 0xff == 0`   the write changes nothing at all -- the saved RBP is
 *                       already 256-aligned. There is no pivot to aim.
 *   * `H & 0xff` small  the landing lands in the 0x20-byte gap between the top
 *                       of `buf` and H (the saved RBP slot, the return address,
 *                       and `handle`'s spilled argument), which the attacker
 *                       does not own.
 *
 * So a single attempt cannot exceed 15/16, and with this frame geometry the
 * expectation is 13/16 == 81.25%. That is a property of the PRIMITIVE, not of
 * the exploit's quality, and both the reference exploit and the executor spend
 * retries rather than claiming determinism.
 *
 * MEASURED, 32 independent attempts with the family's reference exploit
 * (`benchmark/reference_exploits/offbyone_variants_reference.py --rate`):
 * 26/32 == 81.25%, i.e. exactly 13/16. The per-target measured rates for the
 * other two pivot variants are in their own headers and differ from this one,
 * which is the point: the rate is a function of the frame geometry, not of the
 * category.
 *
 * THE PAYLOAD SHAPE, AND THE ALIGNMENT DETAIL THAT IS NOT COSMETIC
 * ---------------------------------------------------------------
 * Because the landing offset is unknown, `buf` is filled with a repeating
 * 16-byte pattern `[p64(win), p64(ret_gadget)]` rather than a chain at a fixed
 * place. `buf` starts 16-aligned and the landing is always `≡ 8 (mod 16)`, so
 * the pivot always lands on the `ret` half, slides one word, and enters `win`
 * with rsp `≡ 8 (mod 16)` -- the parity a function entered by `call` would
 * have. Landing directly on the `win` half instead would enter it 16-aligned
 * and glibc's `system()` faults on a `movaps` with that parity, which is the
 * difference between a shell and a core dump.
 *
 * HELD CONSTANT in every file of this family:
 *   * `win()` -> `system("/bin/sh")`, the single shell site, non-static so it
 *     survives as a symbol whatever else changes;
 *   * the menu, the prompts and the command letters:
 *     `1) info  2) edit  0) quit`, the defect always on '2';
 *   * `main -> handle(c) -> do_*()`: the off-by-one is always two calls deep,
 *     so the frame the pivot corrupts is `handle`'s and `main`'s loop is never
 *     damaged (a failed attempt can therefore be retried in-process);
 *   * `handle()` keeps NO buffer of its own in the four targets that pivot into
 *     the overflowed frame -- 0x100 bytes of locals there would push the
 *     landing gap past 256 and make the primitive unreachable by arithmetic
 *     rather than by hardening. obo_14 varies exactly this on purpose;
 *   * the 0x400-byte total size of the overflowed region, and its ending flush
 *     against the saved RBP;
 *   * cflags (see the `cflags` beside this file -- byte-identical family-wide).
 *
 * Lab fixture. Deliberately vulnerable. Not for use outside this benchmark.
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_SZ 0x400

static void say(const char *s)
{
    write(1, s, strlen(s));
}

/* The single shell site. Non-static so the symbol survives; nothing in the
 * program's own control flow reaches it. */
void win(void)
{
    say("[+] frame pivoted\n");
    system("/bin/sh");
}

static void do_info(void)
{
    say("[*] label service, build 10\n");
}

/* ---------------- THE VARIED AXIS: the mechanism ------------------------- */

/* `<=` instead of `<`: n + 1 iterations, so the caller's n-byte buffer takes
 * n + 1 bytes and the last one is fully attacker-chosen. */
static void read_line(char *dst, size_t n)
{
    size_t i;

    for (i = 0; i <= n; i++) {
        if (read(0, &dst[i], 1) != 1)
            return;
    }
}

/* ---------------- HELD CONSTANT: the frame that gets pivoted -------------- */

static void do_edit(void)
{
    char buf[BUF_SZ];                 /* the ONLY local: ends flush at (%rbp) */

    say("[*] line: ");
    read_line(buf, sizeof buf);       /* writes buf[BUF_SZ] -> saved RBP's LSB */
    say("[+] stored\n");
}

static void handle(char c)
{
    switch (c) {
    case '1': do_info(); break;
    case '2': do_edit(); break;
    default:  say("[-] ?\n"); break;
    }
}

int main(void)
{
    char cmd[16];
    ssize_t n;

    say("== label service ==\n"
        "1) info  2) edit  0) quit\n");
    for (;;) {
        say("> ");
        n = read(0, cmd, sizeof cmd);
        if (n <= 0 || cmd[0] == '0')
            return 0;
        handle(cmd[0]);
    }
}
