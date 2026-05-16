#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "kernel/audit.h"
#include "user/user.h"

static int passed;
static int failed;

static void
check(char *name, int ok)
{
  if(ok){
    printf("[PASS] %s\n", name);
    passed++;
  } else {
    printf("[FAIL] %s\n", name);
    failed++;
  }
}

static int
can_read(char *path)
{
  char c;
  int fd = open(path, O_RDONLY);
  if(fd < 0)
    return 0;
  int n = read(fd, &c, 1);
  close(fd);
  return n >= 0;
}

static int
can_write(char *path)
{
  char c = 'X';
  int fd = open(path, O_WRONLY);
  if(fd < 0)
    return 0;
  int n = write(fd, &c, 1);
  close(fd);
  return n == 1;
}

static int
exec_denied_as_patient(void)
{
  int pid, st;
  char *argv[] = { "echo", "exec-test", 0 };

  if(login("Admin", "Admin123") < 0)
    return 0;
  if(chmod("echo", 0600) < 0)
    return 0;
  if(login("Patient", "Patient123") < 0)
    return 0;

  pid = fork();
  if(pid < 0)
    return 0;
  if(pid == 0){
    if(exec("echo", argv) < 0)
      exit(0);
    exit(1);
  }
  wait(&st);

  login("Admin", "Admin123");
  chmod("echo", 0755);
  return st == 0;
}

int
main(void)
{
  char who[16];
  struct audit_entry *entries;
  struct audit_entry one;
  int n;

  printf("=== Medical Device Security Compliance Report ===\n");

  check("invalid login rejected", login("Patient", "wrong") < 0);
  check("admin login succeeds", login("Admin", "Admin123") == 0);
  memset(who, 0, sizeof(who));
  check("whoami reports Admin", whoami(who, sizeof(who)) == 0 &&
        strcmp(who, "Admin") == 0);

  userdel("tempsec");
  check("admin useradd succeeds", useradd("tempsec", "Temp123", 3, 3) == 0);
  check("admin passwd succeeds", passwd("tempsec", "Temp456") == 0);
  check("admin userdel succeeds", userdel("tempsec") == 0);

  check("patient login succeeds", login("Patient", "Patient123") == 0);
  check("patient reads records", can_read("/patient/records"));
  check("patient cannot write records", !can_write("/patient/records"));
  check("patient reads insulin log", can_read("/dosage/insulin.log"));
  check("patient cannot write insulin log", !can_write("/dosage/insulin.log"));
  check("patient cannot read device config", !can_read("/device/config"));
  check("patient audit denied", auditread(&one, 1) < 0);

  check("doctor login succeeds", login("Doctor", "Doctor123") == 0);
  check("doctor reads patient records", can_read("/patient/records"));
  check("doctor writes insulin log", can_write("/dosage/insulin.log"));
  check("doctor useradd denied", useradd("bad", "Bad123", 4, 4) < 0);

  check("exec permission denial works", exec_denied_as_patient());

  check("admin login restored", login("Admin", "Admin123") == 0);
  check("admin reads device config", can_read("/device/config"));

  entries = malloc(32 * sizeof(struct audit_entry));
  n = entries ? auditread(entries, 32) : -1;
  check("admin audit read succeeds", n > 0);
  if(n > 0){
    printf("audit evidence: entries=%d first(pid=%d uid=%d syscall=%d retval=%d tick=%d)\n",
           n, entries[0].pid, entries[0].uid, entries[0].syscall_num,
           entries[0].retval, entries[0].tick);
  }
  if(entries)
    free(entries);

  printf("Compliance summary: passed=%d failed=%d\n", passed, failed);
  if(failed)
    exit(1);
  exit(0);
}
