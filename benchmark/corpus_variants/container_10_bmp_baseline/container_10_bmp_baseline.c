/*
 * Container-overflow variant corpus -- ANCHOR.
 *
 * The category: a buffer whose size comes from one parsed metadata field, and
 * a fill loop whose length comes from something else entirely (here, "until
 * EOF"). Nothing compares the two, so the overflow is bounded only by how much
 * file the operator hands over.
 *
 * This target is the fixed point of the family: it reproduces the shape of the
 * measured HTB target (snow_scan) as closely as a standalone file can --
 * .bmp extension gate, a 400..900 accept window on the image-size field, a
 * square-dimensions check, a VLA sized from that field, and a byte-at-a-time
 * fill loop driven by EOF whose base pointer and index both live in stack
 * slots the overflow passes through.
 *
 * It exists so that a variant failure can be told apart from a corpus-wide
 * mistake. It is NOT a capability claim: this shape already solved.
 *
 * FLAG{supwngo_bench_container_10_bmp_baseline}
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HDR_LEN 54

/* Deliberate: the accept window is narrow and says nothing about the real
 * dimensions, exactly like the target this models. A payload has to satisfy
 * the header check and then get out of the way. */
#define ACCEPT_MIN 400
#define ACCEPT_MAX 900

static int has_ext(const char *path, const char *ext)
{
    size_t lp = strlen(path), le = strlen(ext);
    return lp > le && strcmp(path + lp - le, ext) == 0;
}

static int load_bitmap(const char *path)
{
    FILE *f;
    unsigned char hdr[HDR_LEN];
    uint32_t data_offset, width, height, image_size;
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
    if (hdr[0] != 'B' || hdr[1] != 'M') {
        puts("[-] not a bitmap");
        return 1;
    }

    memcpy(&data_offset, hdr + 10, 4);
    memcpy(&width, hdr + 18, 4);
    memcpy(&height, hdr + 22, 4);
    memcpy(&image_size, hdr + 34, 4);

    if (image_size < ACCEPT_MIN || image_size > ACCEPT_MAX) {
        printf("[-] image size must be between %dx%d and %dx%d\n",
               20, 20, 30, 30);
        return 1;
    }
    if (width != height) {
        puts("[-] only square bitmaps are supported");
        return 1;
    }

    /* Sized from the metadata field... */
    unsigned char pixels[image_size];
    unsigned char *p = pixels;
    int i = 0;

    /* ...filled until EOF. The index is never compared to image_size. */
    fseek(f, data_offset, SEEK_SET);
    while ((c = fgetc(f)) != EOF) {
        p[i] = (unsigned char)c;
        i++;
    }

    printf("[%u] : PASS\n", image_size);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        puts("usage: scanner <file.bmp>");
        return 1;
    }
    if (!has_ext(argv[1], ".bmp")) {
        puts("[-] only accepting .bmp files");
        return 1;
    }
    return load_bitmap(argv[1]);
}
