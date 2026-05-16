#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "user/user.h"

#define MAX_USERNAME 16
#define MAX_PASSWORD 32
#define MAX_ATTEMPTS 3

static void
readline(char *buf, int max)
{
  int i = 0;
  char c;
  while(i < max - 1){
    if(read(0, &c, 1) != 1) break;
    if(c == '\n') break;
    buf[i++] = c;
  }
  buf[i] = '\0';
}

int
main(void)
{
  char username[MAX_USERNAME];
  char password[MAX_PASSWORD];
  char *sh_argv[] = { "sh", 0 };

  printf("\n");
  printf("=== xv6 Secure Login ===\n");
  printf("IEC 62443 SL-2 Compliant\n");
  printf("\n");

  for(;;){
    int attempts = 0;

    // get username
    printf("login: ");
    readline(username, MAX_USERNAME);

    if(strlen(username) == 0)
      continue;

    // try password up to MAX_ATTEMPTS times
    while(attempts < MAX_ATTEMPTS){
      printf("password: ");
      readline(password, MAX_PASSWORD);

      if(login(username, password) == 0){
        // success
        printf("\nWelcome, %s!\n\n", username);
        exec("sh", sh_argv);
        // if exec returns, something went wrong
        printf("login: exec sh failed\n");
        exit(1);
      }

      attempts++;
      printf("Login incorrect. (%d/%d)\n", attempts, MAX_ATTEMPTS);
    }

    // too many failed attempts
    printf("Too many failed attempts. Try again.\n\n");
  }
}
