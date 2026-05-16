#include "kernel/types.h"
#include "user/user.h"

int main() {
    int x = 42;   // local variable on the stack

    printf("Address of x: %p\n", &x);

    exit(0);
}
