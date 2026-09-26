#include <stdio.h>
#include <unistd.h>
int main(void){ char b[64]; printf("pid=%d\n",(int)getpid()); fflush(stdout); read(0,b,256); return 0; }
