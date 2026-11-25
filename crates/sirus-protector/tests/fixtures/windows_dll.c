#include <stdint.h>

#define SIRUS_DLL_EXPORT __declspec(dllexport)

SIRUS_DLL_EXPORT __attribute__((noinline))
uint64_t sirus_dll_fn(uint64_t a, uint64_t b) {
    if (a > b) {
        return (a * 5u + b) ^ 0x1122334455667788ull;
    }
    return (b ^ a) * 3u + 0x99aabbccddeeff00ull;
}
