#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline))
uint64_t sirus_abi_loop(uint64_t a, uint64_t b) {
    uint64_t accumulator = 0;
    uint64_t index = 0;
    while (index < (a & 7u)) {
        accumulator = (accumulator + b) * 3u;
        index += 1;
    }
    if (a > b) {
        return accumulator ^ (a * 5u + b);
    }
    return accumulator ^ (b - a);
}

int main(int argc, char **argv) {
    uint64_t a = argc > 1 ? strtoull(argv[1], NULL, 0) : 7;
    uint64_t b = argc > 2 ? strtoull(argv[2], NULL, 0) : 3;
    uint64_t iterations = argc > 3 ? strtoull(argv[3], NULL, 0) : 1;
    uint64_t checksum = 0;
    for (uint64_t index = 0; index < iterations; ++index) {
        checksum += sirus_abi_loop(a + (index & 1u), b);
    }
    printf("checksum=%016llx\n", (unsigned long long)checksum);
    return 0;
}
