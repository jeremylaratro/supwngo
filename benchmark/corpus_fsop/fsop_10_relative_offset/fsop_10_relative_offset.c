/*
 * FSOP anchor: two qword writes relative to stdout.
 *
 * The target reads flag.txt into a private buffer immediately before the
 * caller-supplied stdout buffer.  The only disclosure path is to corrupt the
 * live _IO_FILE so a subsequent puts() flush starts at the private buffer.
 * PIE, NX, canary and Full RELRO are all enabled; no control-flow transfer is
 * required, so the category ceiling is FLAG_CAPTURED.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_fsop_10_relative_offset}"
#endif

struct arena {
    char vault[128];
    char output[512];
};

static struct arena state;

static void load_flag(void)
{
    FILE *fp = fopen("flag.txt", "rb");
    size_t n = 0;

    memset(&state, 0, sizeof state);
    if (fp != NULL) {
        n = fread(state.vault, 1, sizeof state.vault - 1, fp);
        fclose(fp);
    }
    if (n == 0)
        memcpy(state.vault, FLAG, sizeof FLAG);
}

int main(void)
{
    long offset;
    unsigned long value;
    int i;

    load_flag();
    if (setvbuf(stdout, state.output, _IOLBF, sizeof state.output) != 0)
        return 1;
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("FSOP relative writer stdout=%p vault=%p flags=%#x\n",
           (void *)stdout, (void *)state.vault, *(unsigned int *)stdout);
    for (i = 0; i < 2; i++) {
        printf("offset: ");
        fflush(stdout);
        if (scanf("%ld", &offset) != 1)
            return 1;
        printf("value: ");
        fflush(stdout);
        if (scanf("%lx", &value) != 1)
            return 1;
        *(unsigned long *)((char *)stdout + offset) = value;
        puts("stored");
    }
    puts("complete");
    return 0;
}
