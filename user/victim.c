#include "kernel/types.h"
#include "user/user.h"

void secret_win() {
    printf("Success! You hijacked the control flow – 221001856\n");
    exit(0);
}

void my_gets(char *buf) {
    char c;
    int i = 0;
    while (1) {
        read(0, &c, 1);
        if (c == '\n') break;
        buf[i++] = c;
    }
}

int main() {
    char buf[16];
    printf("Enter input: \n");
    my_gets(buf);
    printf("You entered: %s\n", buf);
    return 0;
}

