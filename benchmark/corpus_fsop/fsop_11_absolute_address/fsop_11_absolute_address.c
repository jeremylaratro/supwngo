/* FSOP variant: the same FILE corruption reached through absolute writes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FLAG
#define FLAG "FLAG{supwngo_fsop_11_absolute_address}"
#endif

struct arena {
    char vault[160];
    char output[640];
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
    unsigned long address;
    unsigned long data;
    int i;

    load_flag();
    if (setvbuf(stdout, state.output, _IOLBF, sizeof state.output) != 0)
        return 1;
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("FSOP absolute writer stdout=%p vault=%p flags=%#x\n",
           (void *)stdout, (void *)state.vault, *(unsigned int *)stdout);
    for (i = 0; i < 2; i++) {
        printf("address: ");
        fflush(stdout);
        if (scanf("%lx", &address) != 1)
            return 1;
        printf("data: ");
        fflush(stdout);
        if (scanf("%lx", &data) != 1)
            return 1;
        *(unsigned long *)address = data;
        printf("accepted\n");
    }
    printf("finished\n");
    return 0;
}
