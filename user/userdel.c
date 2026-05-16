#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if(argc != 2){
    printf("usage: userdel <username>\n");
    exit(1);
  }

  if(userdel(argv[1]) < 0){
    printf("userdel: failed (not root, or user is root)\n");
    exit(1);
  }

  printf("User '%s' deleted successfully\n", argv[1]);
  exit(0);
}
