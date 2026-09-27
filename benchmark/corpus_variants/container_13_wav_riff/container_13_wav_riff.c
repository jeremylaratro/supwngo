/*
 * Container-overflow variant: A DIFFERENT CONTAINER.
 *
 * Same bug, same frame shape, but the container is RIFF/WAVE rather than BMP:
 * a different magic, a different extension gate, the size field at offset 40
 * instead of 34, and a cross-field consistency check (byte_rate must equal
 * sample_rate * block_align) standing in for the anchor's square-dimensions
 * check.
 *
 * What this is for: an implementation carrying one hardcoded envelope builder
 * emits raw bytes for every other extension, and the target's own validator
 * rejects them before the fill loop is ever reached -- so the failure looks
 * like "not vulnerable" when it is really "could not construct a container".
 * Passing it requires more than one envelope, or a way to derive one.
 *
 * FLAG{supwngo_bench_container_13_wav_riff}
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HDR_LEN 44

/* Deliberate: a different accept window again, so a solver cannot carry the
 * anchor's numbers across containers either. */
#define ACCEPT_MIN 600
#define ACCEPT_MAX 1400

static int has_ext(const char *path, const char *ext)
{
    size_t lp = strlen(path), le = strlen(ext);
    return lp > le && strcmp(path + lp - le, ext) == 0;
}

static int load_wave(const char *path)
{
    FILE *f;
    unsigned char hdr[HDR_LEN];
    uint32_t sample_rate, byte_rate, data_size;
    uint16_t block_align;
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
    if (memcmp(hdr, "RIFF", 4) != 0 || memcmp(hdr + 8, "WAVE", 4) != 0) {
        puts("[-] not a riff wave");
        return 1;
    }
    if (memcmp(hdr + 36, "data", 4) != 0) {
        puts("[-] expects a data chunk at the canonical offset");
        return 1;
    }

    memcpy(&sample_rate, hdr + 24, 4);
    memcpy(&byte_rate, hdr + 28, 4);
    memcpy(&block_align, hdr + 32, 2);
    memcpy(&data_size, hdr + 40, 4);

    if (data_size < ACCEPT_MIN || data_size > ACCEPT_MAX) {
        printf("[-] data chunk must be between %d and %d bytes\n",
               ACCEPT_MIN, ACCEPT_MAX);
        return 1;
    }
    /* A real RIFF invariant, and the analogue of the anchor's square check: a
     * cross-field constraint an envelope builder has to satisfy, not just a
     * range. */
    if (byte_rate != sample_rate * (uint32_t)block_align) {
        puts("[-] inconsistent byte rate");
        return 1;
    }

    /* Sized from the metadata field... */
    unsigned char samples[data_size];
    unsigned char *p = samples;
    int i = 0;

    /* ...filled until EOF. The index is never compared to data_size. */
    while ((c = fgetc(f)) != EOF) {
        p[i] = (unsigned char)c;
        i++;
    }

    printf("[%u] : PASS\n", data_size);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        puts("usage: sampler <file.wav>");
        return 1;
    }
    if (!has_ext(argv[1], ".wav")) {
        puts("[-] only accepting .wav files");
        return 1;
    }
    return load_wave(argv[1]);
}
