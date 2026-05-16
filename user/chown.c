#include "kernel/types.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if(argc != 4){
    printf("usage: chown <uid> <gid> <file>\n");
    exit(1);
  }
  uint uid = atoi(argv[1]);
  uint gid = atoi(argv[2]);
  if(chown(argv[3], uid, gid) < 0){
    printf("chown: failed (not root)\n");
    exit(1);
  }
  printf("ownership changed\n");
  exit(0);
}
