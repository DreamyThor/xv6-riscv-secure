#include "types.h"
#include "param.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"
#include "proc.h"
#include "audit.h"

extern uint ticks;

// private ring buffer — not exposed in audit.h
struct audit_ring {
  struct audit_entry entries[AUDIT_SIZE];
  int head;
  int count;
  struct spinlock lock;
};

static struct audit_ring auditlog;

void
audit_init(void)
{
  initlock(&auditlog.lock, "audit");
  auditlog.head  = 0;
  auditlog.count = 0;
}

void
audit_write(int pid, int uid, int syscall_num, int retval)
{
  acquire(&auditlog.lock);
  struct audit_entry *e = &auditlog.entries[auditlog.head];
  e->pid         = pid;
  e->uid         = uid;
  e->syscall_num = syscall_num;
  e->retval      = retval;
  e->tick        = ticks;
  auditlog.head  = (auditlog.head + 1) % AUDIT_SIZE;
  auditlog.count++;
  release(&auditlog.lock);
}

int
audit_read(uint64 addr, int max_entries)
{
  struct proc *p = myproc();

  if(p->uid != 0)
    return AUDIT_EPERM;

  acquire(&auditlog.lock);

  int total = auditlog.count < AUDIT_SIZE ? auditlog.count : AUDIT_SIZE;
  int n = total < max_entries ? total : max_entries;

  int start = (auditlog.count < AUDIT_SIZE) ? 0 : auditlog.head;

  for(int i = 0; i < n; i++){
    int idx = (start + i) % AUDIT_SIZE;
    if(copyout(p->pagetable, addr + i * sizeof(struct audit_entry),
               (char*)&auditlog.entries[idx],
               sizeof(struct audit_entry)) < 0){
      release(&auditlog.lock);
      return -1;
    }
  }

  release(&auditlog.lock);
  return n;
}
