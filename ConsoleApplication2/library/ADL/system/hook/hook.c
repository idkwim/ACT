#include "hook.h"

typedef struct HOOKEX_INFORMATION
{
    HANDLE ProcessHandle;
    LPVOID lpHook; 
    LPVOID lpProcedure; 
    DWORD dwProcedureSize; 
    LPVOID lpParameter; 
    DWORD dwParameterSize;
}HOOKEX_INFORMATION;

HOOK_INFORMATION CreateHook32(HANDLE ProcessHandle, LPVOID lpHook, LPVOID lpProcedure, DWORD dwProcedureSize, LPVOID lpParameter, DWORD dwParameterSize)
{
    HOOK_INFORMATION ret = {
        0,
    };

    /*
        JmpInstruction holds..
        mov eax, 00 00 00 00 
        jmp eax
    */
    BYTE JmpInstruction[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
    
    //Old protection value
    DWORD dwOldProtection = 0;
    DWORD dwOldProtection2 = 0;
    //Is memory protection changed?
    BOOL IsProtectionChanged = 0;

    ADDRESS ReturnValue = (ADDRESS)NULL;

    //Is not writable & readable
    IsProtectionChanged = lpfnVirtualProtectEx(ProcessHandle, lpHook, sizeof(JmpInstruction), PAGE_EXECUTE_READWRITE, &dwOldProtection);

    //check memory protection
    if (IsProtectionChanged != FALSE)
    {
        //create hook to use lpfnWriteProcessMemory API

        //Create procedure code page
        LPBYTE lpCode = lpfnVirtualAllocEx(ProcessHandle, NULL, dwProcedureSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (lpCode == NULL)
        {
            //printf("VirtualAlloc API faild; line=%d; code=%d\n", __LINE__, GetLastError());
            return ret;
        }

        if (lpfnWriteProcessMemory(ProcessHandle, lpCode, lpProcedure, dwProcedureSize, NULL) == FALSE)
        {
            //printf("lpfnWriteProcessMemory API faild; line=%d; code=%d\n", __LINE__, GetLastError());
            lpfnVirtualFreeEx(ProcessHandle, lpCode, 0, MEM_RELEASE);

            return ret;
        }

        //Create procedure code parameter
        LPVOID lpParamArea = lpfnVirtualAllocEx(ProcessHandle, NULL, dwParameterSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (lpParamArea == NULL)
        {
            return ret;
        }

        if (lpfnWriteProcessMemory(ProcessHandle, lpParamArea, lpParameter, dwParameterSize, NULL) == FALSE)
        {
            //printf("lpfnWriteProcessMemory API faild; line=%d; code=%d\n", __LINE__, GetLastError());
            lpfnVirtualFreeEx(ProcessHandle, lpCode, 0, MEM_RELEASE);
            lpfnVirtualFreeEx(ProcessHandle, lpParamArea, 0, MEM_RELEASE);

            return ret;
        }

        BYTE PointerVariableInsturction[] = {0xCC, 0xCC, 0xCC, 0xCC};

        //KMP algorithm
        DWORD FindPointerVariableIndex;
        for (FindPointerVariableIndex = 0; FindPointerVariableIndex != dwProcedureSize; FindPointerVariableIndex++)
        {
            BOOL IsFinded = TRUE;

            for (DWORD FindNext = 0;
                 FindNext != sizeof(PointerVariableInsturction);
                 FindNext++)
            {
                if (((BYTE *)lpProcedure)[FindNext + FindPointerVariableIndex] != PointerVariableInsturction[FindNext])
                {
                    IsFinded = FALSE;
                    break;
                }
            }

            if (IsFinded == TRUE)
                break;
            //printf("0x%02X ", lpCode[FindPointerVariableIndex]);
        }
        //FindPointerVariableIndex += sizeof(PointerVariableInsturction);

        lpfnWriteProcessMemory(ProcessHandle, lpCode + FindPointerVariableIndex, &lpParamArea, sizeof(LPVOID), NULL);
        //lpCode + FindPointerVariableIndex

        //create mov & jmp instruction
        for (int i = 0; i != sizeof(LPVOID); i++)
            JmpInstruction[i + 1] = ((BYTE *)&lpCode)[i];

        /*
        JmpInstruction holds..
        jmp lpProcedure
        */

        lpfnWriteProcessMemory(ProcessHandle, lpHook, JmpInstruction, sizeof(JmpInstruction), NULL);
        lpfnVirtualProtectEx(ProcessHandle, lpHook, sizeof(JmpInstruction), dwOldProtection, &dwOldProtection2);

        ret.Code = (ADDRESS)lpCode;
        ret.Param = (ADDRESS)lpParamArea;
    }
    else
    {
        ReturnValue = (ADDRESS)NULL;
    }

    return ret;
}

HOOK_INFORMATION CreateHook64(HANDLE ProcessHandle, LPVOID lpHook, LPVOID lpProcedure, DWORD dwProcedureSize, LPVOID lpParameter, DWORD dwParameterSize)
{
    HOOK_INFORMATION ret = {
        0,
    };
    /*
        holds Jmp Instruction..

        mov rax, 00 00 00 00 00 00 00 00
        jmp rax
    */
    BYTE JmpInstruction[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};

    //Old protection value
    DWORD dwOldProtection = 0;
    DWORD dwOldProtection2 = 0;
    //Is memory protection changed?
    BOOL IsProtectionChanged = 0;

    ADDRESS ReturnValue = (ADDRESS)NULL;

    //Is not writable & readable

    //create hook to use lpfnWriteProcessMemory API

    //Create procedure code page
    LPBYTE lpCode = lpfnVirtualAllocEx(ProcessHandle, NULL, dwProcedureSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpCode == NULL)
    {
        // printf("VirtualAlloc API faild; line=%d; code=%d\n", __LINE__, GetLastError());
        return ret;
    }

    if (lpfnWriteProcessMemory(ProcessHandle, lpCode, lpProcedure, dwProcedureSize, NULL) == FALSE)
    {
        // printf("lpfnWriteProcessMemory API faild; line=%d; code=%d\n", __LINE__, GetLastError());
        lpfnVirtualFreeEx(ProcessHandle, lpCode, 0, MEM_RELEASE);

        return ret;
    }
    
    //Create procedure code parameter
    LPVOID lpParamArea = lpfnVirtualAllocEx(ProcessHandle, NULL, dwParameterSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (lpParamArea == NULL)
    {
        // printf("VirtualAlloc API faild; line=%d; code=%d\n", __LINE__, GetLastError());
        return ret;
    }

    if (lpfnWriteProcessMemory(ProcessHandle, lpParamArea, lpParameter, dwParameterSize, NULL) == FALSE)
    {
        // printf("lpfnWriteProcessMemory API faild; line=%d; code=%d\n", __LINE__, GetLastError());
        lpfnVirtualFreeEx(ProcessHandle, lpCode, 0, MEM_RELEASE);
        lpfnVirtualFreeEx(ProcessHandle, lpParamArea, 0, MEM_RELEASE);

        return ret;
    }

    BYTE PointerVariableInsturction[] = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};

    //KMP algorithm
    DWORD FindPointerVariableIndex;
    for (FindPointerVariableIndex = 0; FindPointerVariableIndex != dwProcedureSize; FindPointerVariableIndex++)
    {
        BOOL IsFinded = TRUE;

        for (DWORD FindNext = 0;
             FindNext != sizeof(PointerVariableInsturction);
             FindNext++)
        {
            if (((BYTE *)lpProcedure)[FindNext + FindPointerVariableIndex] != PointerVariableInsturction[FindNext])
            {
                IsFinded = FALSE;
                break;
            }
        }

        if (IsFinded == TRUE)
            break;
        //printf("0x%02X ", lpCode[FindPointerVariableIndex]);
    }
    //FindPointerVariableIndex += sizeof(PointerVariableInsturction);

    lpfnWriteProcessMemory(ProcessHandle, lpCode + FindPointerVariableIndex, &lpParamArea, sizeof(LPVOID), NULL);
    //lpCode + FindPointerVariableIndex

    //create mov & jmp instruction
    for (int i = 0; i != sizeof(LPVOID); i++)
        JmpInstruction[i + 2] = ((BYTE *)&lpCode)[i];

    /*
        JmpInstruction holds..
        jmp lpProcedure
        */

    lpfnVirtualProtectEx(ProcessHandle, lpHook, sizeof(JmpInstruction), PAGE_EXECUTE_READWRITE, &dwOldProtection);
    lpfnWriteProcessMemory(ProcessHandle, lpHook, JmpInstruction, sizeof(JmpInstruction), NULL);
    lpfnVirtualProtectEx(ProcessHandle, lpHook, sizeof(JmpInstruction), dwOldProtection, &dwOldProtection2);

    ret.Code = (ADDRESS)lpCode;
    ret.Param = (ADDRESS)lpParamArea;

    return ret;
}

HOOK_INFORMATION CreateHookEx(HANDLE ProcessHandle, LPVOID lpHook, LPVOID lpProcedure, DWORD dwProcedureSize, LPVOID lpParameter, DWORD dwParameterSize)
{
    #ifdef _WIN64
    return CreateHook64(ProcessHandle, lpHook, lpProcedure, dwProcedureSize, lpParameter, dwParameterSize);
    #else
    return CreateHook32(ProcessHandle, lpHook, lpProcedure, dwProcedureSize, lpParameter, dwParameterSize);
    #endif
}

HOOK_INFORMATION CreateHookEx2(HOOKEX_INFORMATION information)
{
    #ifdef _WIN64
    return CreateHook64(information.ProcessHandle, 
        information.lpHook, 
        information.lpProcedure, 
        information.dwProcedureSize, 
        information.lpParameter, 
        information.dwParameterSize);

    #else
    return CreateHook32(information.ProcessHandle, 
        information.lpHook, 
        information.lpProcedure, 
        information.dwProcedureSize, 
        information.lpParameter, 
        information.dwParameterSize);
    #endif
}

 void FreeVirtualBuffer(HANDLE ProcessHandle, LPVOID lpAddress)
{
    lpfnVirtualFreeEx(ProcessHandle, lpAddress, 0, MEM_RELEASE);
}

LPVOID CreateVirtualBuffer(HANDLE ProcessHandle, LPVOID lpAddress, LPVOID Buffer, DWORD BufferSize, BOOL *lpOptinalReturnValue)
{
    BOOL ReturnValue = FALSE;

    LPVOID VirtualBuffer = lpfnVirtualAllocEx(ProcessHandle, lpAddress, BufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (VirtualBuffer == NULL)
    {
        if (lpOptinalReturnValue != NULL)
            *lpOptinalReturnValue = FALSE;

        return NULL;
    }

    ReturnValue = lpfnWriteProcessMemory(ProcessHandle, VirtualBuffer, Buffer, BufferSize, NULL);
    if (ReturnValue == FALSE)
    {
        if (lpOptinalReturnValue != NULL)
            *lpOptinalReturnValue = FALSE;

        FreeVirtualBuffer(ProcessHandle, VirtualBuffer);
        return NULL;
    }

    if (lpOptinalReturnValue != NULL)
        *lpOptinalReturnValue = TRUE;

    return VirtualBuffer;
}



int CmpProcessData(HANDLE ProcessHandle, LPVOID FindSource, BYTE *FindData, DWORD SizeOfSource)
{
    BYTE *Buffer = LocalAlloc(LPTR, SizeOfSource);
    if (Buffer == NULL)
        return FALSE;

    lpfnReadProcessMemory(ProcessHandle, FindSource, Buffer, SizeOfSource, NULL);

    int i = 0;
    for (; i != SizeOfSource; i++)
    {
        if (Buffer[i] != FindData[i])
            break;
    }

    LocalFree(Buffer);

    if (i == SizeOfSource)
        return TRUE;

    return FALSE;
}

int IsAlreadyHooked(HANDLE ProcessHandle, LPVOID API)
{
#ifdef _WIN64
    BYTE JmpInstruction[] = {0x48, 0xb8};
#else
    BYTE JmpInstruction[] = {0xb8};
#endif

    return CmpProcessData(ProcessHandle, API, JmpInstruction, sizeof(JmpInstruction));
}
