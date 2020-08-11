void WINAPI FreeProcessList(SNAPSHOT_INFO Object)
{
    MEMSET((LPVOID)Object.AbsoluteObject, 0, Object.Size);

    lpfn_VirtualFree((LPVOID)Object.AbsoluteObject, 0, MEM_RELEASE);
    lpfn_VirtualFree((LPVOID)Object.AbsoluteObject, Object.Size, MEM_DECOMMIT);

    return;
}

SNAPSHOT_INFO WINAPI CreateProcessList()
{
    LPFN_NTQUERYSYSTEMINFORMATION SysCall =
        (LPFN_NTQUERYSYSTEMINFORMATION)GetVirtualProcedure(__ADL_GLOBAL_INFO__.nt_info, "NtQuerySystemInformation");

    BYTE *Buffer = NULL;
    BYTE *ReturnBuffer = NULL;

    ULONG SystemInformationLength;
    ULONG ReturnLength;

    NTSTATUS ReturnValue;

    ReturnValue = SysCall(SystemProcessInformation, NULL, 0, &SystemInformationLength);
    
    Buffer = (BYTE*)lpfn_VirtualAlloc(NULL, SystemInformationLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    ReturnValue = SysCall(SystemProcessInformation, Buffer, SystemInformationLength, &ReturnLength);

    ReturnBuffer = Buffer;

    SNAPSHOT_INFO Object;
    Object.AbsoluteObject = (ADDRESS)ReturnBuffer;
    Object.CurrentObject = (ADDRESS)ReturnBuffer;
    
    SYSTEM_PROCESS_INFORMATION *SystemProcessInformation = (SYSTEM_PROCESS_INFORMATION *)Object.CurrentObject;
    Object.CurrentObject += SystemProcessInformation->NextEntryOffset;
    Object.Size = SystemInformationLength;
    
    Object.Flag = FALSE;

    return Object;
}

BOOL WINAPI GetProcessData(SNAPSHOT_INFO *Object, PROCESS_DATA *Information)
{
    SYSTEM_PROCESS_INFORMATION *SystemProcessInformation = (SYSTEM_PROCESS_INFORMATION *)Object->CurrentObject;

    if(Information != NULL)
    {
        Information->ProcessName = SystemProcessInformation->ImageName;
        Information->ProcessId = SystemProcessInformation->UniqueProcessId;
        Information->ProcessHandle = NULL;

        if(Object->Flag == TRUE) return FALSE;
    }

    Object->CurrentObject += SystemProcessInformation->NextEntryOffset;
    
    if(SystemProcessInformation->NextEntryOffset == 0) 
    {
        Object->Flag = TRUE;
    }

    return TRUE;
}

HANDLE WINAPI GetProcessHandle(HANDLE ProcessId)
{
	HANDLE ProcessHandle;
    CLIENT_ID ClientId = {0,};   
    ClientId.UniqueProcess = ProcessId;
    OBJECT_ATTRIBUTES Object = { sizeof(Object) };
    
    LPFN(NtOpenProcess)(
        &ProcessHandle, 
        PROCESS_ALL_ACCESS,
        &Object, 
        &ClientId);

    return ProcessHandle;
}

NTSTATUS WINAPI GetProcessHandleEx(HANDLE ProcessId, HANDLE ProcessHandle)
{
    CLIENT_ID ClientId = {0,};   
    ClientId.UniqueProcess = ProcessId;
    OBJECT_ATTRIBUTES Object = { sizeof(Object) };
    
    return LPFN(NtOpenProcess)(
        &ProcessHandle, 
        PROCESS_ALL_ACCESS,
        &Object, 
        &ClientId);
}

LPVOID WINAPI VirtualAllocate(HANDLE ProcessHandle, SIZE_T RegionSize, ULONG Protection)
{
    LPVOID VirtualAddress = NULL;
    LPFN(NtAllocateVirtualMemory)(ProcessHandle, (LPVOID*)&VirtualAddress, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return VirtualAddress;
}

void WINAPI VirtualDelete(HANDLE ProcessHandle, LPVOID *VirtualAddress, SIZE_T RegionSize)
{
    SIZE_T ReleaseSize = 0;

    LPFN(NtFreeVirtualMemory)(ProcessHandle, VirtualAddress, &ReleaseSize, MEM_RELEASE);
    LPFN(NtFreeVirtualMemory)(ProcessHandle, VirtualAddress, &RegionSize, MEM_DECOMMIT);
}

NTSTATUS WINAPI VirtualWrite(HANDLE ProcessHandle, LPVOID VirtualAddress, LPCVOID Buffer, SIZE_T BufferSize)
{
    return LPFN(NtWriteVirtualMemory) (ProcessHandle, VirtualAddress, (LPVOID)Buffer, BufferSize, NULL);
}

NTSTATUS WINAPI VirtualRead(HANDLE ProcessHandle, LPVOID VirtualAddress, LPVOID Buffer, SIZE_T BufferSize)
{
    return LPFN(NtReadVirtualMemory) (ProcessHandle, VirtualAddress, Buffer, BufferSize, NULL);
}

LPVOID WINAPI CreateVirtualArea(HANDLE ProcessHandle, LPVOID Buffer, DWORD BufferSize, BOOL *lpOptinalReturnValue)
{
    BOOL ReturnValue = FALSE;

    LPVOID VirtualBuffer = VirtualAllocate(ProcessHandle, BufferSize, PAGE_EXECUTE_READWRITE);
    if (VirtualBuffer == NULL)
    {
        if (lpOptinalReturnValue != NULL)
            *lpOptinalReturnValue = FALSE;

        return NULL;
    }
    
    ReturnValue = VirtualWrite(ProcessHandle, VirtualBuffer, Buffer, BufferSize);
    if (ReturnValue != FALSE)
    {
        if (lpOptinalReturnValue != NULL)
            *lpOptinalReturnValue = FALSE;

        VirtualDelete(ProcessHandle, &VirtualBuffer, BufferSize);
        return NULL;
    }

    if (lpOptinalReturnValue != NULL)
        *lpOptinalReturnValue = TRUE;

    return VirtualBuffer;
}

/*

typedef NTSYSAPI NTSTATUS (NTAPI *LPFN_NTPROTECTVIRTUALMEMORY)(
  IN HANDLE               ProcessHandle,
  IN OUT PVOID            *BaseAddress,
  IN OUT PULONG           NumberOfBytesToProtect,
  IN ULONG                NewAccessProtection,
  OUT PULONG              OldAccessProtection 
);
*/

NTSTATUS WINAPI VirtualProtection(
    IN HANDLE               ProcessHandle,
    IN OUT PVOID            BaseAddress,
    IN OUT ULONG            NumberOfBytesToProtect,
    IN ULONG                NewAccessProtection,
    OUT PULONG              OldAccessProtection 
)
{
    LPVOID temp = BaseAddress;
    ULONG size = NumberOfBytesToProtect;

    return LPFN(NtProtectVirtualMemory) (
       ProcessHandle,
       &temp,
       &size,
       PAGE_EXECUTE_READWRITE,
       OldAccessProtection
    );
}

NTSTATUS WINAPI CreateVirtualHook(HOOK_INFO *VirtualHookInfo)
{
    LPBYTE VirtualProcedure = (LPBYTE)CreateVirtualArea(
        VirtualHookInfo->ProcessHandle, 
        VirtualHookInfo->Procedure, 
        VirtualHookInfo->ProcedureSize,
        NULL
        );

    if(VirtualProcedure == NULL) return TRUE;

    LPVOID ProcedureParameter = CreateVirtualArea(
        VirtualHookInfo->ProcessHandle, 
        VirtualHookInfo->Parameter, 
        VirtualHookInfo->ParameterSize,
        NULL
        );

    if(ProcedureParameter == NULL) 
    {
        VirtualDelete(
            VirtualHookInfo->ProcessHandle, 
            (LPVOID*)&VirtualProcedure, 
            VirtualHookInfo->ProcedureSize
            );
        
        return TRUE;
    }

	VirtualHookInfo->HookCode = VirtualProcedure;
	VirtualHookInfo->HookParameter = ProcedureParameter;

    int int3 = 0xCC;

    //Find parameter pointer
    int distance = 0;
    for (; ((LPBYTE)VirtualHookInfo->Procedure)[distance] != int3; distance += 1);
    //distance -= 1;

    //edit parameter pointer
    VirtualWrite(
        VirtualHookInfo->ProcessHandle, 
        ((LPBYTE)VirtualProcedure) + distance,
        &ProcedureParameter,
        sizeof(LPVOID)
        );

    //printf("%p\n", VirtualProcedure);

    /*
    32
    BYTE JmpInstruction[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
    64
    BYTE JmpInstruction[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
    */

#ifdef _WIN64
BYTE JmpInstruction[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
int JmpDistance = 2;
#else
BYTE JmpInstruction[] = {0xb8, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
int JmpDistance = 1;
#endif

    MEMCOPY(JmpInstruction + JmpDistance, &VirtualProcedure, sizeof(LPVOID));
    
    ULONG NewProtection = PAGE_EXECUTE_READWRITE;
    ULONG OldProtection = 0;
    ULONG ProtectionSize = 32;
    
    /*
    LPFN(NtProtectVirtualMemory) (
       VirtualHookInfo->ProcessHandle,
       &temp,
       &ProtectionSize,
       PAGE_EXECUTE_READWRITE,
       &OldProtection
    );
    */

    VirtualProtection(
        VirtualHookInfo->ProcessHandle,
        VirtualHookInfo->Hooker,
        ProtectionSize,
        PAGE_EXECUTE_READWRITE,
        &OldProtection
    );
    
    //create hook
    NTSTATUS ret = VirtualWrite(
        VirtualHookInfo->ProcessHandle,
        VirtualHookInfo->Hooker,
        JmpInstruction,
        sizeof(JmpInstruction)
        );

    VirtualProtection(
        VirtualHookInfo->ProcessHandle,
        VirtualHookInfo->Hooker,
        ProtectionSize,
        PAGE_READWRITE,
        &OldProtection
    );

    return ret;
}