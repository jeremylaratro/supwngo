/*
 * Container-overflow variant: NO EXTENSION GATE, NO STANDARD FORMAT.
 *
 * The bug and the frame shape are the anchor's, but nothing about the container
 * is guessable from a table of known file formats: the path is accepted whatever
 * it is called, and the header is a 16-byte private structure (magic "SCAN",
 * a version that must be 1, the size field, and the offset the data starts at).
 *
 * What this is for: two assumptions at once. First, an implementation that
 * derives candidate extensions from the target's own strings finds nothing to
 * derive here and must still proceed. Second, the header is short and private,
 * so the only way through the validator is to read the checks out of the
 * binary -- there is no format library to fall back on.
 *
 * FLAG{supwngo_bench_container_14_raw_no_ext}
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HDR_LEN 16

/* Deliberate: a third distinct accept window. */
#define ACCEPT_MIN 1024
#define ACCEPT_MAX 1536

static int load_scan(const char *path)
{
    FILE *f;
    unsigned char hdr[HDR_LEN];
    uint32_t version, payload_size, data_offset;
    int c;

    f = fopen(path, "rb");
    if (f == NULL) {
        puts("[-] open failed");
        return 1;
    }
    if (fread(hdr, 1, HDR_LEN, f) != HDR_LEN) {
        puts("[-] short header");
        return 1;
    }
    if (memcmp(hdr, "SCAN", 4) != 0) {
        puts("[-] bad magic");
        return 1;
    }

    memcpy(&version, hdr + 4, 4);
    memcpy(&payload_size, hdr + 8, 4);
    memcpy(&data_offset, hdr + 12, 4);

    if (version != 1) {
        puts("[-] unsupported version");
        return 1;
    }
    if (payload_size < ACCEPT_MIN || payload_size > ACCEPT_MAX) {
        printf("[-] payload must be between %d and %d bytes\n",
               ACCEPT_MIN, ACCEPT_MAX);
        return 1;
    }
    if (data_offset < HDR_LEN) {
        puts("[-] data offset overlaps the header");
        return 1;
    }

    /* Sized from the metadata field... */
    unsigned char payload[payload_size];
    unsigned char *p = payload;
    int i = 0;

    /* ...filled until EOF. The index is never compared to payload_size. */
    fseek(f, data_offset, SEEK_SET);
    while ((c = fgetc(f)) != EOF) {
        p[i] = (unsigned char)c;
        i++;
    }

    printf("[%u] : PASS\n", payload_size);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        puts("usage: rawscan <file>");
        return 1;
    }
    /* No extension gate on purpose: any path is accepted. */
    return load_scan(argv[1]);
}
