#ifndef HOOKS_H
#define HOOKS_H

#include <windows.h>

//fill parameter pointer to CC
#define ADDRESS_64 (LPVOID)0xCCCCCCCCCCCCCCCC
#define ADDRESS_32 (LPVOID)0xCCCCCCCC

#ifdef _WIN64
    //64
#define HOOK_PARAM ADDRESS_64 
#define DEFAULT_ADDRESS ADDRESS_64 
#else 
    //32
#define HOOK_PARAM ADDRESS_32
#define DEFAULT_ADDRESS ADDRESS_64 
#endif 

typedef struct HOOK_INFORMATION
{
    DWORD ProcessId;
    ADDRESS Code;
    ADDRESS Param;
} HOOK_INFORMATION;

HOOK_INFORMATION CreateHook32(HANDLE ProcessHandle, LPVOID lpHook, LPVOID lpProcedure, DWORD dwProcedureSize, LPVOID lpParameter, DWORD dwParameterSize);
HOOK_INFORMATION CreateHook64(HANDLE ProcessHandle, LPVOID lpHook, LPVOID lpProcedure, DWORD dwProcedureSize, LPVOID lpParameter, DWORD dwParameterSize);

HOOK_INFORMATION CreateHookEx(HANDLE ProcessHandle, LPVOID lpHook, LPVOID lpProcedure, DWORD dwProcedureSize, LPVOID lpParameter, DWORD dwParameterSize);

void FreeVirtualBuffer(HANDLE ProcessHandle, LPVOID lpAddress);
LPVOID CreateVirtualBuffer(HANDLE ProcessHandle, LPVOID lpAddress, LPVOID Buffer, DWORD BufferSize, BOOL *lpOptinalReturnValue);

int IsAlreadyHooked(HANDLE ProcessHandle, LPVOID API);

#endif