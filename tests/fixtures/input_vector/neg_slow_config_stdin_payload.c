/*
 * Adversarial fixture for the probe's stage-3 timeout basis.
 *
 * Shape: reads a CONFIG file named in argv (so stage 2 legitimately fires),
 * does work PROPORTIONAL to that file's size (so a 4096-byte file is merely
 * SLOW, not corrupted), and takes its actual payload from stdin.
 *
 * MEASURED: 32 bytes completes in ~0.4s, 4096 bytes exceeds 20s. On the
 * probe's 5s budget the large run times out, so stage 3 sees a difference
 * and returns "file-candidate" -- a FALSE POSITIVE, since the payload
 * channel is stdin.
 *
 * This is harmless by construction rather than by luck: the probe is
 * advisory and can never commit a DeliverySpec (Sprint 2' REVISION 3), so a
 * wrong advisory cannot suppress a working stdin delivery. The fixture
 * exists to keep the limitation MEASURED and pinned -- the accompanying test
 * asserts the verdict comes with evidence["stage3_basis"] == "timeout", so
 * nobody later mistakes this for strong evidence.
 *
 * That label is NOT a discriminator, and must not be used as one: a genuine
 * file sink can share it. mech_line_text.c really does take its payload from
 * a file and also times out on the 4096-byte probe file (no newline, so its
 * fgets blocks). "timeout" therefore means "this stage proved nothing",
 * never "this is not a file target".
 */
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char b[64];
    unsigned long acc = 0;
    int c;
    FILE *f;

    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (f) {
            while ((c = fgetc(f)) != EOF) {
                volatile unsigned long i;
                for (i = 0; i < 3000000UL; i++) acc += i ^ c;
            }
            fclose(f);
            printf("cfg scanned %lu\n", acc & 0xff);
        } else {
            puts("cfg missing");
        }
    }
    fflush(stdout);
    read(0, b, 256);
    return 0;
}
