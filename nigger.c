#include <stdio.h>

void main() {
    int x = 10;
    printf("%x %x\n", &x, (int*)(x + 1))
}