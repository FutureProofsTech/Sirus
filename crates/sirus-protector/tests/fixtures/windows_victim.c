#include <stdint.h>
#include <stdio.h>

#ifdef _MSC_VER
#define SIRUS_NOINLINE __declspec(noinline)
#else
#define SIRUS_NOINLINE __attribute__((noinline))
#endif

SIRUS_NOINLINE uint64_t sirus_win_check(uint64_t a, uint64_t b) {
    if (a > b) {
        return ((a * 3u) + b) ^ 0xa5a55a5a12345678ull;
    }
    return (b ^ a) + 0x123456789abcdef0ull;
}

SIRUS_NOINLINE uint64_t sirus_win_mix(uint64_t a, uint64_t b) {
    uint64_t accumulator = 0;
    uint64_t index = 0;
    while (index < (a & 7u)) {
        accumulator = (accumulator + b) * 3u;
        index += 1;
    }
    return accumulator ^ 0x0123456789abcdefull;
}

int main(void) {
    const uint64_t pairs[4][2] = {
        {7u, 3u}, {3u, 7u}, {0u, 0u}, {123456789u, 5u}
    };
    for (unsigned i = 0; i < 4; ++i) {
        printf("%llu %llu\n",
               (unsigned long long)sirus_win_check(pairs[i][0], pairs[i][1]),
               (unsigned long long)sirus_win_mix(pairs[i][0], pairs[i][1]));
    }
    return 0;
}
