#include "kernel/types.h"
#include "kernel/audit.h"
#include "user/user.h"

#define MAX_ENTRIES 128

// syscall number to name
static const char*
syscall_name(int num)
{
  switch(num){
    case 5:  return "read";
    case 7:  return "exec";
    case 15: return "open";
    case 16: return "write";
    case 21: return "close";
    case 22: return "login";
    case 23: return "useradd";
    case 24: return "userdel";
    case 27: return "chmod";
    case 28: return "chown";
    case 29: return "auditread";
    default: return "unknown";
  }
}

int
main(void)
{
  struct audit_entry *buf = malloc(MAX_ENTRIES * sizeof(struct audit_entry));
  if(buf == 0){
    printf("audit: out of memory\n");
    exit(1);
  }

  int n = auditread(buf, MAX_ENTRIES);
  if(n < 0){
    printf("audit: permission denied or read failed\n");
    free(buf);
    exit(1);
  }

  printf("\n=== xv6 Syscall Audit Log ===\n");
  printf("tick pid uid syscall retval\n");
  printf("----------------------------------------\n");

  for(int i = 0; i < n; i++){
    if(buf[i].syscall_num == 5 || buf[i].syscall_num == 16)
      continue;
    printf("%d %d %d %s %d\n",
           buf[i].tick,
           buf[i].pid,
           buf[i].uid,
           syscall_name(buf[i].syscall_num),
           buf[i].retval);
  }

  printf("----------------------------------------\n");
  printf("Total entries: %d\n\n", n);
  free(buf);
  exit(0);
}
