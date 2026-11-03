#ifndef CROSS_WINDOWS_H
#define CROSS_WINDOWS_H
#include <stddef.h>
#include <stdint.h>

#define WINAPI __stdcall
#define VOID void
typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef long LONG;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef size_t SIZE_T;
typedef uintptr_t UINT_PTR;
typedef intptr_t INT_PTR;
typedef uintptr_t ULONG_PTR;
typedef intptr_t LONG_PTR;
typedef uintptr_t DWORD_PTR;
typedef void *PVOID;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef void *HANDLE;
typedef void *HMODULE;
typedef char CHAR;
typedef wchar_t WCHAR;
typedef const char *LPCSTR;
typedef const wchar_t *LPCWSTR;
typedef int (WINAPI *FARPROC)(void);
typedef LONG HRESULT;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define TEXT(x) x
#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_RELEASE 0x00008000
#define MEM_LARGE_PAGES 0x20000000
#define PAGE_READWRITE 0x04

__declspec(dllimport) LPVOID WINAPI VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
__declspec(dllimport) BOOL WINAPI VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
__declspec(dllimport) SIZE_T WINAPI GetLargePageMinimum(VOID);
__declspec(dllimport) HMODULE WINAPI GetModuleHandleA(LPCSTR lpModuleName);
#define GetModuleHandle GetModuleHandleA
__declspec(dllimport) FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
__declspec(dllimport) DWORD WINAPI GetVersion(VOID);
__declspec(dllimport) BOOL WINAPI IsProcessorFeaturePresent(DWORD ProcessorFeature);

#endif
