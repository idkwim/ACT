#include "../ntdll.h"
#include "../root.h"

#include <stdio.h>

#ifndef PROCESS_H
#define PROCESS_H

typedef struct DYNAMIC_OBJECT
{
    ADDRESS AbsoluteObject;
    ADDRESS CurrentObject;
    ULONG Size;
    BOOL Flag;
}DYNAMIC_OBJECT;

void WINAPI FreeProcessList(DYNAMIC_OBJECT *Object)
{
    memset((LPVOID)Object->AbsoluteObject, 0, Object->Size);

    VirtualFree((LPVOID)Object->AbsoluteObject, 0, MEM_RELEASE);
    VirtualFree((LPVOID)Object->AbsoluteObject, Object->Size, MEM_DECOMMIT);

    return;
}

DYNAMIC_OBJECT WINAPI CreateProcessList()
{
    /*    
    LPFN_RTLGETNATIVESYSTEMFINFORMATION Syscall =
        (LPFN_RTLGETNATIVESYSTEMFINFORMATION)GetProcAddress(GetModuleHandle("ntdll"), "RtlGetNativeSystemInformation");
    */
    LPFN_RTLGETNATIVESYSTEMFINFORMATION Syscall =
        (LPFN_RTLGETNATIVESYSTEMFINFORMATION)GetProcedureAddress(GetModuleAddress("ntdll"), "RtlGetNativeSystemInformation");

    BYTE *Buffer = NULL;
    BYTE *ReturnBuffer = NULL;

    ULONG SystemInformationLength;
    ULONG ReturnLength;

    NTSTATUS ReturnValue;

    ReturnValue = Syscall(SystemProcessInformation, NULL, 0, &SystemInformationLength);
    Buffer = (BYTE*)VirtualAlloc(NULL, SystemInformationLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ReturnValue = Syscall(SystemProcessInformation, Buffer, SystemInformationLength, &ReturnLength);

    ReturnBuffer = Buffer;

    DYNAMIC_OBJECT Object;
    Object.AbsoluteObject = (ADDRESS)ReturnBuffer;
    Object.CurrentObject = (ADDRESS)ReturnBuffer;
    
    SYSTEM_PROCESS_INFORMATION *SystemProcessInformation = (SYSTEM_PROCESS_INFORMATION *)Object.CurrentObject;
    Object.CurrentObject += SystemProcessInformation->NextEntryOffset;
    Object.Size = SystemInformationLength;
    
    Object.Flag = FALSE;

    return Object;
}

typedef struct PROCESS_DATA
{
    UNICODE_STRING ProcessName;
    HANDLE ProcessId;
    LPVOID Reserved[4];
}PROCESS_DATA;

void InitProcessObject(DYNAMIC_OBJECT *Object)
{
    Object->CurrentObject = Object->AbsoluteObject;
}

BOOL GetProcessData(DYNAMIC_OBJECT *Object, PROCESS_DATA *Information)
{
    SYSTEM_PROCESS_INFORMATION *SystemProcessInformation = (SYSTEM_PROCESS_INFORMATION *)Object->CurrentObject;

    if(Information != NULL)
    {
        Information->ProcessName = SystemProcessInformation->ImageName;
        Information->ProcessId = SystemProcessInformation->UniqueProcessId;

        if(Object->Flag == TRUE) return FALSE;
    }

    Object->CurrentObject += SystemProcessInformation->NextEntryOffset;
    
    if(SystemProcessInformation->NextEntryOffset == 0) 
    {
        Object->Flag = TRUE;
    }

    return TRUE;
}

DWORD ProcessNameToProcessId(const WCHAR *ProcessName, HANDLE *ProcessesList, DWORD ProcessesListSize)
{
    DWORD ReturnValue = FALSE;

    DYNAMIC_OBJECT Object = CreateProcessList();
    PROCESS_DATA ProcessData;

    DWORD ProcessesListIndex = 0;

    for (;;)
    {
        if (GetProcessData(&Object, &ProcessData) == FALSE)
            break;

        if (ProcessData.ProcessName.Buffer != NULL)
        {
            if (memcmp(ProcessData.ProcessName.Buffer, ProcessName, ProcessData.ProcessName.Length) == 0)
            {
                if(ProcessesList != NULL)
                {
                    ProcessesList[ProcessesListIndex] = ProcessData.ProcessId;
                }
                
                if(ProcessesListSize != 0)
                {
                    if(ProcessesListSize <= ProcessesListIndex * sizeof(HANDLE)) break;
                }
                
                ProcessesListIndex += 1;
            }
        }
    }

    ReturnValue = ProcessesListIndex;
    FreeProcessList(&Object);

    return ReturnValue;
}

#endif