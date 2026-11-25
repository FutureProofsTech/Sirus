#include <stdio.h>

static const unsigned long sirus_call_table[4] = {
    0x0123456789abcdefUL, 0xfedcba9876543210UL,
    0x1111222233334444UL, 0x5555666677778888UL
};

__attribute__((noinline, used))
unsigned long sirus_win_callee(unsigned long a, unsigned long b) {
    return sirus_call_table[a & 3] ^ (b + 0x55);
}

__attribute__((noinline, used))
unsigned long sirus_win_caller(unsigned long a, unsigned long b) {
    unsigned long value = sirus_win_callee(a, b);
    return value + (a & 1) + 7;
}

int main(void) {
    printf("%lu\n", sirus_win_caller(3, 4));
    return 0;
}
