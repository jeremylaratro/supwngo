#include <stdio.h>
#include <unistd.h>
int main(int argc,char**argv){ char b[64]; char cfg[32];
  if(argc>1){ FILE*f=fopen(argv[1],"rb");
    if(f){ size_t n=fread(cfg,1,16,f); fclose(f); printf("cfg loaded %zu\n",n); }
    else puts("cfg missing"); }
  fflush(stdout); read(0,b,256); return 0; }
