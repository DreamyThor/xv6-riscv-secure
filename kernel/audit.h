#ifndef AUDIT_H
#define AUDIT_H

#define AUDIT_SIZE   512
#define AUDIT_EPERM  -2

struct audit_entry {
  int  pid;
  int  uid;
  int  syscall_num;
  int  retval;
  uint tick;
};

#endif
