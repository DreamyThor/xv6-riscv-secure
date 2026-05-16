#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if(argc != 3){
    printf("usage: passwd <username> <newpassword>\n");
    exit(1);
  }

  if(passwd(argv[1], argv[2]) < 0){
    printf("passwd: failed (permission denied or user not found)\n");
    exit(1);
  }

  printf("Password updated for '%s'\n", argv[1]);
  exit(0);
}
