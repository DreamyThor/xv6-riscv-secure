#include "kernel/types.h"
#include "user/user.h"

static uint
parse_octal(const char *s)
{
  uint n = 0;
  while(*s >= '0' && *s <= '7')
    n = n * 8 + (*s++ - '0');
  return n;
}

int
main(int argc, char *argv[])
{
  if(argc != 3){
    printf("usage: chmod <mode> <file>\n");
    exit(1);
  }
  uint mode = parse_octal(argv[1]);
  if(chmod(argv[2], mode) < 0){
    printf("chmod: failed (not owner or root)\n");
    exit(1);
  }
  printf("mode changed\n");
  exit(0);
}
