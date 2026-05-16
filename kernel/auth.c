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

// convert string to integer
static int
atoi(const char *s)
{
  int n = 0;
  while(*s >= '0' && *s <= '9')
    n = n * 10 + (*s++ - '0');
  return n;
}

// convert integer to string
static void
itoa(int n, char *buf)
{
  int i = 0;
  char tmp[8];
  if(n == 0){
    buf[0] = '0';
    buf[1] = '\0';
    return;
  }
  while(n > 0){
    tmp[i++] = '0' + (n % 10);
    n /= 10;
  }
  // reverse
  for(int j = 0; j < i; j++)
    buf[j] = tmp[i - j - 1];
  buf[i] = '\0';
}

// FNV-1a hash of a plaintext password
// writes 8 hex chars + null terminator into out[9]
void
passwd_hash(const char *password, char *out)
{
  uint hash = 2166136261u;
  const char *p = password;
  while(*p){
    hash ^= (uchar)*p++;
    hash *= 16777619u;
  }
  // convert to hex string
  const char *hex = "0123456789abcdef";
  for(int i = 7; i >= 0; i--){
    out[i] = hex[hash & 0xf];
    hash >>= 4;
  }
  out[8] = '\0';
}

// reads /etc/passwd line by line
// if username matches, fills entry and returns 1
// returns 0 if not found
int
passwd_lookup(const char *username, struct userentry *entry)
{
  struct inode *ip;
  char buf[MAX_LINE];
  char line[MAX_LINE];
  int linelen = 0;
  uint offset = 0;
  int n;

  // open /etc/passwd
  if((ip = namei(PASSWD_PATH)) == 0)
    return 0;

  ilock(ip);

  // read file byte by byte, build lines
  while((n = readi(ip, 0, (uint64)buf, offset, sizeof(buf))) > 0){
    offset += n;
    for(int i = 0; i < n; i++){
      if(buf[i] == '\n' || linelen == MAX_LINE - 1){
        line[linelen] = '\0';
        linelen = 0;

        // parse line: username:hash:uid:gid
        char *tok = line;
        char *fields[4];
        int f = 0;

        // split by ':'
        for(char *c = line; *c && f < 4; c++){
          if(*c == ':'){
            *c = '\0';
            fields[f++] = tok;
            tok = c + 1;
          }
        }
        fields[f++] = tok; // last field

        if(f != 4) continue; // malformed line, skip

        // check if this is the user we want
        if(strncmp(fields[0], username, MAX_USERNAME) == 0){
          safestrcpy(entry->username, fields[0], MAX_USERNAME);
          safestrcpy(entry->passhash, fields[1], MAX_HASH);
          entry->uid = atoi(fields[2]);
          entry->gid = atoi(fields[3]);
          iunlock(ip);
          iput(ip);
          return 1;
        }
      } else {
        line[linelen++] = buf[i];
      }
    }
  }

  iunlock(ip);
  iput(ip);
  return 0;
}

// returns uid on success, -1 on failure
int
authenticate(const char *username, const char *password)
{
  struct userentry entry;
  char hash[MAX_HASH];

  if(passwd_lookup(username, &entry) == 0)
    return -1;  // user not found

  passwd_hash(password, hash);

  if(strncmp(hash, entry.passhash, MAX_HASH) != 0)
    return -1;  // wrong password

  return entry.uid;
}

int
passwd_append(const char *username, const char *password, int uid, int gid)
{
  struct inode *ip;
  struct userentry existing;
  char line[MAX_LINE];
  char hash[MAX_HASH];
  int len;

  // reject if user already exists
  if(passwd_lookup(username, &existing) == 1)
    return -1;

  passwd_hash(password, hash);

  // build the new line
  // format: username:hash:uid:gid\n
  len = 0;
  char uidstr[8], gidstr[8];
  itoa(uid, uidstr);
  itoa(gid, gidstr);

  // manually build line into buf
  memmove(line, username, strlen(username));
  len += strlen(username);
  line[len++] = ':';
  memmove(line + len, hash, 8); len += 8;
  line[len++] = ':';
  memmove(line + len, uidstr, strlen(uidstr)); len += strlen(uidstr);
  line[len++] = ':';
  memmove(line + len, gidstr, strlen(gidstr)); len += strlen(gidstr);
  line[len++] = '\n';

  if((ip = namei(PASSWD_PATH)) == 0)
    return -1;

  ilock(ip);
  begin_op();
  // append at end of file
  writei(ip, 0, (uint64)line, ip->size, len);
  end_op();
  iunlock(ip);
  iput(ip);
  return 0;
}

// these are more complex — they require rewriting the file
// we read everything into a buffer, skip/modify the target line,
// then write the whole file back

int
passwd_remove(const char *username)
{
  struct inode *ip;
  char inbuf[MAX_USERS * MAX_LINE];
  char outbuf[MAX_USERS * MAX_LINE];
  int inlen, outlen = 0;
  int found = 0;

  if((ip = namei(PASSWD_PATH)) == 0)
    return -1;

  begin_op();
  ilock(ip);
  inlen = readi(ip, 0, (uint64)inbuf, 0, sizeof(inbuf));

  // copy all lines except the one matching username
  int start = 0;
  int ulen = strlen(username);
  for(int i = 0; i < inlen; i++){
    if(i == inlen || inbuf[i] == '\n'){
      int linelen = i - start;
      if(linelen > ulen &&
         strncmp(inbuf + start, username, ulen) == 0 &&
         inbuf[start + ulen] == ':'){
        found = 1;
      } else if(linelen > 0){
        // keep this line
        memmove(outbuf + outlen, inbuf + start, linelen);
        outlen += linelen;
        outbuf[outlen++] = '\n';
      }
      start = i + 1;
    }
  }

  // rewrite file
  ip->size = 0;  // truncate
  writei(ip, 0, (uint64)outbuf, 0, outlen);
  iupdate(ip);
  iunlock(ip);
  iput(ip);
  end_op();
  return found ? 0 : -1;
}

int
passwd_update(const char *username, const char *newpassword, int caller_uid)
{
  struct userentry entry;
  if(passwd_lookup(username, &entry) == 0)
    return -1;

  // only root or the user themselves can change password
  if(caller_uid != 0 && caller_uid != entry.uid)
    return -1;

  // remove old entry then append updated one
  if(passwd_remove(username) < 0)
    return -1;

  return passwd_append(username, newpassword, entry.uid, entry.gid);
}
