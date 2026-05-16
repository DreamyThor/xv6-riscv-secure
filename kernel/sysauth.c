#include "types.h"
#include "param.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "proc.h"
#include "auth.h"
#include "audit.h"

#define KERNEL_AUDIT
#include "audit.h"

static int
append_str(char *buf, int off, const char *s)
{
  while(*s)
    buf[off++] = *s++;
  return off;
}

static int
append_int(char *buf, int off, int n)
{
  char tmp[16];
  int i = 0;

  if(n < 0){
    buf[off++] = '-';
    n = -n;
  }

  if(n == 0){
    buf[off++] = '0';
    return off;
  }

  while(n > 0){
    tmp[i++] = '0' + (n % 10);
    n /= 10;
  }
  while(i > 0)
    buf[off++] = tmp[--i];
  return off;
}

// sys_login: authenticate a user and update proc identity
// args: username (char*), password (char*)
uint64
sys_login(void)
{
  char username[MAX_USERNAME];
  char password[MAX_USERNAME];
  struct proc *p = myproc();
  struct userentry entry;

  argstr(0, username, MAX_USERNAME);
  argstr(1, password, MAX_USERNAME);

  int uid = authenticate(username, password);
  if(uid < 0)
    return -1;  // bad credentials
    
  if(passwd_lookup(username, &entry) == 0)
    return -1;

  // update process identity
  p->uid = uid;
  p->gid = entry.gid;
  p->authenticated = 1;
  safestrcpy(p->username, username, MAX_USERNAME);

  return 0;
}

// sys_whoami: copy current username into userspace buffer
// args: buf (char*), size (int)
uint64
sys_whoami(void)
{
  uint64 addr;
  int size;
  struct proc *p = myproc();

  if(!p->authenticated)
    return -1;

  argaddr(0, &addr);
  argint(1, &size);

  int len = strlen(p->username) + 1;
  if(size <= 0 || len > size)
    return -1;

  if(copyout(p->pagetable, addr, p->username, len) < 0)
    return -1;

  return 0;
}

// sys_useradd: add a new user to /etc/passwd
// args: username (char*), password (char*), uid (int), gid (int)
uint64
sys_useradd(void)
{
  char username[MAX_USERNAME];
  char password[MAX_USERNAME];
  int uid, gid;
  struct proc *p = myproc();

  // only root can add users
  if(p->uid != 0)
    return -1;

  argstr(0, username, MAX_USERNAME);
  argstr(1, password, MAX_USERNAME);
  argint(2, &uid);
  argint(3, &gid);

  return passwd_append(username, password, uid, gid);
}

// sys_userdel: remove a user from /etc/passwd
// args: username (char*)
uint64
sys_userdel(void)
{
  char username[MAX_USERNAME];
  struct proc *p = myproc();

  // only root can delete users
  if(p->uid != 0)
    return -1;

  argstr(0, username, MAX_USERNAME);

  // prevent deleting root
  if(strncmp(username, "root", MAX_USERNAME) == 0)
    return -1;

  return passwd_remove(username);
}

// sys_passwd: change a user's password
// args: username (char*), newpassword (char*)
uint64
sys_passwd(void)
{
  char username[MAX_USERNAME];
  char newpassword[MAX_USERNAME];
  struct proc *p = myproc();

  argstr(0, username, MAX_USERNAME);
  argstr(1, newpassword, MAX_USERNAME);

  return passwd_update(username, newpassword, p->uid);
}

// sys_chmod: change file permission bits
// only owner or root can change permissions
uint64
sys_chmod(void)
{
   char path[128];
  uint mode;
  struct inode *ip;
  struct proc *p = myproc();

  argstr(0, path, 128);
  argint(1, (int*)&mode);

  begin_op();                    

  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }

  ilock(ip);

  if(p->uid != 0 && p->uid != ip->uid){
    iunlock(ip);
    iput(ip);
    end_op();
    return -1;
  }

  ip->mode = mode;
  iupdate(ip);
  iunlock(ip);
  iput(ip);
  end_op();                     
  return 0;
}

// sys_chown: change file owner
// only root can change ownership
uint64
sys_chown(void)
{
  char path[128];
  uint uid, gid;
  struct inode *ip;
  struct proc *p = myproc();

  // only root can chown
  if(p->uid != 0)
    return -1;

  argstr(0, path, 128);
  argint(1, (int*)&uid);
  argint(2, (int*)&gid);
  
  begin_op();

  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }

  ilock(ip);
  ip->uid = uid;
  ip->gid = gid;
  iupdate(ip);
  iunlock(ip);
  iput(ip);
  end_op();
  return 0;
}

uint64
sys_auditread(void)
{
  uint64 addr;
  int max;

  argaddr(0, &addr);
  argint(1, &max);

  int n = audit_read(addr, max);
  if(n == AUDIT_EPERM)
    return -1;
  if(n < 0)
    return n;

  // write to /audit/syscall.log
  if(n > 0){
    struct inode *ip;
    begin_op();
    if((ip = namei("/audit/syscall.log")) != 0){
      ilock(ip);
      ip->size = 0;
      struct proc *p = myproc();
      struct audit_entry *entries = (struct audit_entry*)kalloc();
      char *line = (char*)kalloc();
      if(entries != 0){
        int bytes = n * sizeof(struct audit_entry);
        if(bytes <= PGSIZE &&
           copyin(p->pagetable, (char*)entries, addr, bytes) == 0){
          int offset = 0;
          for(int i = 0; i < n; i++){
            if(line == 0)
              break;
            int len = 0;
            len = append_str(line, len, "tick=");
            len = append_int(line, len, entries[i].tick);
            len = append_str(line, len, " pid=");
            len = append_int(line, len, entries[i].pid);
            len = append_str(line, len, " uid=");
            len = append_int(line, len, entries[i].uid);
            len = append_str(line, len, " syscall=");
            len = append_int(line, len, entries[i].syscall_num);
            len = append_str(line, len, " retval=");
            len = append_int(line, len, entries[i].retval);
            line[len++] = '\n';
            writei(ip, 0, (uint64)line, offset, len);
            offset += len;
          }
        }
      }
      if(line != 0)
        kfree((void*)line);
      if(entries != 0)
        kfree((void*)entries);
      iupdate(ip);
      iunlock(ip);
    }
    end_op();
  }

  return n;
}
