#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if(argc != 5){
    printf("usage: useradd <username> <password> <uid> <gid>\n");
    exit(1);
  }

  int uid = atoi(argv[3]);
  int gid = atoi(argv[4]);

  if(useradd(argv[1], argv[2], uid, gid) < 0){
    printf("useradd: failed (not root, or user already exists)\n");
    exit(1);
  }

  printf("User '%s' added successfully\n", argv[1]);
  exit(0);
}
