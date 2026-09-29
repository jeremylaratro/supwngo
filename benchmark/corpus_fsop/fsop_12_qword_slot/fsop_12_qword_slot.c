/* FSOP variant: signed qword slots relative to stdout, decimal values. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_fsop_12_qword_slot}"
#endif

struct arena {
    char vault[192];
    char output[768];
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
    long slot;
    unsigned long word;
    int i;

    load_flag();
    if (setvbuf(stdout, state.output, _IOLBF, sizeof state.output) != 0)
        return 1;
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("FSOP slot writer stdout=%p vault=%p flags=%#x\n",
           (void *)stdout, (void *)state.vault, *(unsigned int *)stdout);
    for (i = 0; i < 2; i++) {
        printf("slot: ");
        fflush(stdout);
        if (scanf("%ld", &slot) != 1)
            return 1;
        printf("word: ");
        fflush(stdout);
        if (scanf("%lu", &word) != 1)
            return 1;
        ((unsigned long *)stdout)[slot] = word;
        puts("written");
    }
    puts("done");
    return 0;
}
