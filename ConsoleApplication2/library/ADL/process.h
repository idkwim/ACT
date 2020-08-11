#ifndef _ADL_PROCESS_H
#define _ADL_PROCESS_H

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

typedef struct SNAPSHOT_INFO
{
    ADDRESS AbsoluteObject;
    ADDRESS CurrentObject;
    ULONG Size;
    BOOL Flag;
}SNAPSHOT_INFO;

typedef struct PROCESS_DATA
{
    UNICODE_STRING ProcessName;
    HANDLE ProcessId;
    HANDLE ProcessHandle;
}PROCESS_DATA;



void WINAPI FreeProcessList(SNAPSHOT_INFO Object);
SNAPSHOT_INFO WINAPI CreateProcessList();
void WINAPI InitProcessObject(SNAPSHOT_INFO *Object);
BOOL WINAPI GetProcessData(SNAPSHOT_INFO *Object, PROCESS_DATA *Information);

HANDLE WINAPI GetProcessHandle(HANDLE ProcessId);
NTSTATUS WINAPI GetProcessHandleEx(HANDLE ProcessId, HANDLE ProcessHandle);
#define CloseProcessHandle(X) LPFN(NtClose)(X)
#define CloseProcessHandleEx(X) LPFN(NtClose)(X.ProcessHandle)

LPVOID WINAPI VirtualAllocate(HANDLE ProcessHandle, SIZE_T RegionSize, ULONG Protection);
void WINAPI VirtualDelete(HANDLE ProcessHandle, LPVOID *VirtualAddress, SIZE_T RegionSize);

NTSTATUS WINAPI VirtualWrite(HANDLE ProcessHandle, LPVOID VirtualAddress, LPCVOID Buffer, SIZE_T BufferSize);
NTSTATUS WINAPI VirtualRead(HANDLE ProcessHandle, LPVOID VirtualAddress, LPVOID Buffer, SIZE_T BufferSize);

LPVOID WINAPI CreateVirtualArea(HANDLE ProcessHandle, LPVOID Buffer, DWORD BufferSize, BOOL *lpOptinalReturnValue);
#define FreeVirtualArea(ProcessHandle, lpAddress, Size) VirtualDelete(ProcessHandle, &lpAddress, Size)

typedef struct HOOK_INFO
{
    // non-optional
    HANDLE ProcessHandle;

    // non-optional
    LPVOID Hooker;

    // non-optional
    LPVOID Procedure;
    DWORD ProcedureSize;

    // optional
    LPVOID Parameter;
    DWORD ParameterSize;

	// optinal
	LPVOID HookCode;
	LPVOID HookParameter;
		
	NTSTATUS Return;

	LPVOID Reserved;

} HOOK_INFO;

typedef struct VIRUTAL_HOOK_INFORMATION
{
    ADDRESS Code;
    ADDRESS Param;
} VIRUTAL_HOOK_INFORMATION;

NTSTATUS WINAPI CreateVirtualHook(HOOK_INFO *VirtualHookInfo);

#include "process.c"

#endif