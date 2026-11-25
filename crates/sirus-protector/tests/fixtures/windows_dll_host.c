#include <stdint.h>
#include <stdio.h>
#include <windows.h>

typedef uint64_t (*sirus_dll_fn)(uint64_t, uint64_t);

int main(void) {
    HMODULE module = LoadLibraryA("dll.dll");
    if (module == NULL) {
        printf("load-failed %lu\n", GetLastError());
        return 2;
    }
    sirus_dll_fn target =
        (sirus_dll_fn)(void *)GetProcAddress(module, "sirus_dll_fn");
    if (target == NULL) {
        printf("symbol-failed\n");
        return 3;
    }
    printf("%llu\n", (unsigned long long)target(7, 3));
    return 0;
}
