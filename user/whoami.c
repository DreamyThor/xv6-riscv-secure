#include "kernel/types.h"
#include "user/user.h"

int
main(void)
{
  char buf[16];
  if(whoami(buf, 16) < 0){
    printf("whoami: not logged in\n");
    exit(1);
  }
  printf("%s\n", buf);
  exit(0);
}
