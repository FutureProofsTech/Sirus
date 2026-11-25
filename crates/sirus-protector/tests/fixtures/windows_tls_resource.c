#include <stdint.h>
#include <stdio.h>
#include <windows.h>

static void NTAPI sirus_tls_callback(PVOID module, DWORD reason, PVOID reserved) {
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        printf("tls-attach\n");
    }
}

__attribute__((section(".CRT$XLB"), used))
static PIMAGE_TLS_CALLBACK sirus_tls_entry = sirus_tls_callback;

__attribute__((noinline))
uint64_t sirus_tls_target(uint64_t a, uint64_t b) {
    return (a * 5u + b) ^ 0xa5a55a5a12345678ull;
}

int main(void) {
    HRSRC resource = FindResourceA(NULL, MAKEINTRESOURCEA(101), RT_RCDATA);
    if (resource == NULL) {
        printf("resource-missing %lu\n", GetLastError());
        return 2;
    }
    HGLOBAL loaded = LoadResource(NULL, resource);
    const char *bytes = (const char *)LockResource(loaded);
    printf("resource=%s value=%llu\n",
           bytes == NULL ? "null" : bytes,
           (unsigned long long)sirus_tls_target(7, 3));
    return 0;
}
