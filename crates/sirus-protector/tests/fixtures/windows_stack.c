#include <stdio.h>

__attribute__((noinline, used))
unsigned long sirus_win_stack(
    unsigned long a, unsigned long b, unsigned long c, unsigned long d,
    unsigned long e, unsigned long f, unsigned long g, unsigned long h) {
    return a ^ (b + c) ^ (d * 3) ^ (e >> 2) ^ (f << 1) ^ (g * 5) ^ (h + 7);
}

int main(void) {
    printf("%lu\n", sirus_win_stack(1, 2, 3, 4, 5, 6, 7, 8));
    return 0;
}
