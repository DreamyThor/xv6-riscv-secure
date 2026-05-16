#define MAX_USERS    16
#define MAX_USERNAME 16
#define MAX_HASH     9    // 8 hex chars + null terminator
#define MAX_LINE     64   // max chars per passwd line
#define PASSWD_PATH  "/etc/passwd"

// Roles derived from uid
#define ROLE_ADMIN    0
#define ROLE_PATIENT  1
#define ROLE_DOCTOR   2

//Permission bit masks
#ifndef S_IRUSR
#define S_IRUSR  0400   // owner read
#define S_IWUSR  0200   // owner write
#define S_IXUSR  0100   // owner execute
#define S_IRGRP  0040   // group read
#define S_IWGRP  0020   // group write
#define S_IXGRP  0010   // group execute
#define S_IROTH  0004   // other read
#define S_IWOTH  0002   // other write
#define S_IXOTH  0001   // other execute

#define S_IRWXU  0700   // owner all
#define S_IRWXG  0070   // group all
#define S_IRWXO  0007   // other all
#endif

// In-memory representation of one passwd entry
struct userentry {
  char username[MAX_USERNAME];
  char passhash[MAX_HASH];
  int  uid;
  int  gid;
};

// --- function signatures (implemented in auth.c) ---

// Hash a plaintext password using FNV-1a
// Returns the hash as an 8-char hex string written into 'out'

void         
passwd_hash(const char *password, char *out);

// Parse /etc/passwd and find a matching username
// Returns 1 if found, 0 if not — fills 'entry' with the result

int          
passwd_lookup(const char *username, struct userentry *entry);

// Verify username + plaintext password against /etc/passwd
// Returns uid on success, -1 on failure

int          
authenticate(const char *username, const char *password);

// Write a new entry into /etc/passwd (used by useradd)
// Caller must be root (uid == 0)

int          
passwd_append(const char *username, const char *password, int uid, int gid);

// Remove an entry from /etc/passwd (used by userdel)
// Caller must be root (uid == 0)

int          
passwd_remove(const char *username);

// Update password for an existing user (used by passwd syscall)
// Root can change anyone's password; users can only change their own

int          
passwd_update(const char *username, const char *newpassword, int caller_uid);
