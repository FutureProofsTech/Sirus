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

typedef uint64_t (*sirus_abi_fn)(uint64_t, uint64_t);

extern uint64_t sirus_abi_xmm_check(sirus_abi_fn target, uint64_t a, uint64_t b);

SIRUS_NOINLINE uint64_t sirus_abi_target(uint64_t a, uint64_t b) {
    return (a * 5u + b) ^ (a >> 3);
}

SIRUS_NOINLINE uint64_t sirus_abi_large(uint64_t a, uint64_t b) {
    volatile uint8_t buffer[32768];
    for (unsigned index = 0; index < sizeof(buffer); ++index) {
        buffer[index] = (uint8_t)(index ^ a);
    }
    uint64_t value = sirus_abi_target(a, b);
    return value ^ buffer[12346] ^ buffer[(a & 0x3ffu)];
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const uint64_t pairs[4][2] = {
        {7u, 3u}, {3u, 7u}, {0u, 0u}, {123456789u, 5u}
    };
    for (unsigned i = 0; i < 4; ++i) {
        printf("%llu %llu\n",
               (unsigned long long)sirus_win_check(pairs[i][0], pairs[i][1]),
               (unsigned long long)sirus_win_mix(pairs[i][0], pairs[i][1]));
    }
    volatile sirus_abi_fn indirect = sirus_abi_target;
    fprintf(stderr, "abi-start\n");
    const uint64_t direct = sirus_abi_target(9u, 4u);
    fprintf(stderr, "abi-direct %llu\n", (unsigned long long)direct);
    const uint64_t pointer = indirect(9u, 4u);
    fprintf(stderr, "abi-pointer %llu\n", (unsigned long long)pointer);
    const uint64_t xmm = sirus_abi_xmm_check(indirect, 9u, 4u);
    fprintf(stderr, "abi-xmm %llu\n", (unsigned long long)xmm);
    const uint64_t large = sirus_abi_large(9u, 4u);
    fprintf(stderr, "abi-large %llu\n", (unsigned long long)large);
    printf("abi %llu %llu %llu %llu\n",
           (unsigned long long)direct,
           (unsigned long long)pointer,
           (unsigned long long)xmm,
           (unsigned long long)large);
    return 0;
}
