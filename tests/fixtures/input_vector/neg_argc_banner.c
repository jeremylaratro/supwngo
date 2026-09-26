#include <stdio.h>
#include <unistd.h>
int main(int argc,char**argv){ char b[64];
  if(argc>1) puts("mode: with-arg"); else puts("mode: no-arg");
  fflush(stdout); read(0,b,256); return 0; }
