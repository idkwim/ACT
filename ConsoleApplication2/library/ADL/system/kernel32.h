#include "root.h"
#include <windows.h>

#ifndef _KERNEL32_H
#define _KERNEL32_H

/*
typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;
*/

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
    VOID
    );

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;


typedef PPEB (*LPFN_GETPEB) ();


LPFN_GETPEB GetPEB;
ADDRESS GetModuleAddress(const char *ModuleName)
{
    PEB *peb;

    ADDRESS hModule = 0;
    ADDRESS ProcAddress = 0;

    /*
    0x64 0xa1, 0x30, 0x00, 0x00, 0x00, 0xC3
    0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xc3
    */

    //get peb base address
    peb = GetPEB();

    //get ntdll address

    //first flink = self
    //second flink = ntdll.dll
    //...

    int flag = TRUE;

    ADDRESS *Flink = NULL;
    ADDRESS *FirstFlink = NULL;

    ADDRESS DllBase = 0;
    ADDRESS DllName = 0;

    Flink = (ADDRESS *)peb->Ldr->InMemoryOrderModuleList.Flink;
    FirstFlink = Flink;

    for (;;)
    {
        if((ADDRESS *)*Flink == NULL) return (ADDRESS)NULL;

        Flink = (ADDRESS *)*Flink;

        DllBase = (ADDRESS)Flink;
        DllBase += sizeof(PVOID) * 4;

        DllName = (ADDRESS)Flink;

#ifdef _WIN64
        DllName += (sizeof(PVOID) * 4 + sizeof(PVOID) * 5 + (sizeof(USHORT) * 2) * 2);
#else
        DllName += (sizeof(PVOID) * 4 + sizeof(PVOID) * 5 + sizeof(USHORT) * 2);
#endif // _WIN64

        int f = FALSE;
        int i = 0, j = 0;
        WCHAR *lpDllName = (WCHAR *)*(ADDRESS *)DllName;
        
        for (;;)
        {
            char word = ((char *)lpDllName)[i];
            char temp = ModuleName[j];
            
            if (word == 0 || temp == 0)
            {
                f = TRUE;
                break;
            } 
			
            if (word >= 'A' && word <= 'Z') word += 32;
            if (temp >= 'A' && temp <= 'Z') temp += 32;

            if (temp != word) break;
        

            i += 2;
            j++;
        }

        if (f == TRUE) break;
        if( ((ADDRESS)FirstFlink) == **(ADDRESS**)Flink) return (ADDRESS)NULL;
    }

    hModule = *(ADDRESS *)DllBase;

    return hModule;
}

DWORD GetProcedureNumber(ADDRESS hModule)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    int *ExportTableRva;
    int NameIndex = 0;
    ADDRESS ExportTableVa;
    ADDRESS ExportNames;
    PIMAGE_EXPORT_DIRECTORY ExportTableHeader;

    pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + hModule);

    ExportTableRva = (int *)(&pNtHeader->OptionalHeader.DataDirectory[0]);
    ExportTableVa = (ADDRESS)*ExportTableRva;
    ExportTableVa += hModule;

    ExportTableHeader = (PIMAGE_EXPORT_DIRECTORY)ExportTableVa;
    ExportNames = ExportTableHeader->AddressOfNames;
    ExportNames += hModule;

    int *NameRVA = (int *)((ADDRESS)ExportTableHeader->AddressOfNames + hModule);

    return (DWORD)ExportTableHeader->NumberOfFunctions - 1;
}

ADDRESS GetProcedureAddress(ADDRESS hModule, const char *lpProcName)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    int *ExportTableRva;
    int NameIndex = 0;
    ADDRESS ExportTableVa;
    ADDRESS ExportNames;
    PIMAGE_EXPORT_DIRECTORY ExportTableHeader;

    pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + hModule);

    ExportTableRva = (int *)(&pNtHeader->OptionalHeader.DataDirectory[0]);
    ExportTableVa = (ADDRESS)*ExportTableRva;
    ExportTableVa += hModule;

    ExportTableHeader = (PIMAGE_EXPORT_DIRECTORY)ExportTableVa;
    ExportNames = ExportTableHeader->AddressOfNames;
    ExportNames += hModule;

    int *NameRVA = (int *)((ADDRESS)ExportTableHeader->AddressOfNames + hModule);

    int i = ExportTableHeader->NumberOfNames - 1;
    
    for(;;)
    {
        int j = 0; 
        for(;; j++)
        {
            if( ((char *) ((int)NameRVA[i] + hModule)) [j] == 0) break;
            if( ((char *) ((int)NameRVA[i] + hModule)) [j] != lpProcName[j]) 
            {
                j = -1;
                break;
            }
        }

        if(j != -1) break;

        i -= 1;
    }
    
    WORD *lpOrdinals = (WORD *)(ADDRESS)(ExportTableHeader->AddressOfNameOrdinals + hModule);
    int *lpAddresses = (int *)(ADDRESS)(ExportTableHeader->AddressOfFunctions + hModule);
    
    return lpAddresses[lpOrdinals[i]] + hModule;
}

ADDRESS GetProcedureAddressNameFromIndex(ADDRESS hModule, DWORD ProcedureIndex)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    int* ExportTableRva;
    int NameIndex = 0;
    ADDRESS ExportTableVa;
    ADDRESS ExportNames;
    PIMAGE_EXPORT_DIRECTORY ExportTableHeader;

    pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + hModule);

    ExportTableRva = (int*)(&pNtHeader->OptionalHeader.DataDirectory[0]);
    ExportTableVa = (ADDRESS)*ExportTableRva;
    ExportTableVa += hModule;

    ExportTableHeader = (PIMAGE_EXPORT_DIRECTORY)ExportTableVa;
    ExportNames = ExportTableHeader->AddressOfNames;
    ExportNames += hModule;

    int* NameRVA = (int*)((ADDRESS)ExportTableHeader->AddressOfNames + hModule);

    return (ADDRESS)((char*)((int)NameRVA[ProcedureIndex] + hModule));
}

ADDRESS GetProcedureAddressFromIndex(ADDRESS hModule, DWORD ProcedureIndex)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    int *ExportTableRva;
    int NameIndex = 0;
    ADDRESS ExportTableVa;
    ADDRESS ExportNames;
    PIMAGE_EXPORT_DIRECTORY ExportTableHeader;

    pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + hModule);

    ExportTableRva = (int *)(&pNtHeader->OptionalHeader.DataDirectory[0]);
    ExportTableVa = (ADDRESS)*ExportTableRva;
    ExportTableVa += hModule;

    ExportTableHeader = (PIMAGE_EXPORT_DIRECTORY)ExportTableVa;
    ExportNames = ExportTableHeader->AddressOfNames;
    ExportNames += hModule;

    int *NameRVA = (int *)((ADDRESS)ExportTableHeader->AddressOfNames + hModule);

    DWORD ProcedureNumber = ExportTableHeader->NumberOfNames - 1;
	
	if(ProcedureNumber < ProcedureIndex) return 0;
	
    WORD *lpOrdinals = (WORD *)(ADDRESS)(ExportTableHeader->AddressOfNameOrdinals + hModule);
    int *lpAddresses = (int *)(ADDRESS)(ExportTableHeader->AddressOfFunctions + hModule);
    
    return lpAddresses[lpOrdinals[ProcedureIndex]] + hModule;
}

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0
}PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (WINAPI * LPFN_NTQUERYPROCESSINFORMATION)(
  IN HANDLE           ProcessHandle,
  IN PROCESSINFOCLASS ProcessInformationClass,
  OUT PVOID           ProcessInformation,
  IN ULONG            ProcessInformationLength,
  OUT PULONG          ReturnLength
);

ADDRESS GetRemoteProcessModuleName(HANDLE ProcessHandle, char *Name, DWORD Index)
{	
	PROCESS_BASIC_INFORMATION ProcessInformation;
	
	LPFN_NTQUERYPROCESSINFORMATION LPFN(NtQueryInformationProcess);
	
	LPFN(NtQueryInformationProcess) = (LPFN_NTQUERYPROCESSINFORMATION)GetProcedureAddress(
		GetModuleAddress("ntdll.dll"), 
		"NtQueryInformationProcess"
		);
	
	// printf("\n");
	// printf("ntdll!NtQueryInformationProcess:%p\n", LPFN(NtQueryInformationProcess));
	
	ULONG ReturnLength = 0;
	NTSTATUS ReturnError = LPFN(NtQueryInformationProcess)(
		ProcessHandle,
		ProcessBasicInformation,
		&ProcessInformation,
		sizeof(ProcessInformation),
		&ReturnLength
	);
	
	// printf("PEB:\t\t\t\t%p\n", ProcessInformation.PebBaseAddress);
	
	PEB peb;
	ReadProcessMemory(
		ProcessHandle,
		ProcessInformation.PebBaseAddress,
		&peb,
		sizeof(peb),
		NULL
		);
		
	// printf("Loaded Information:\t\t%p\n", peb.Ldr);
	
	PEB_LDR_DATA LdrData;
	BYTE LdrTableEntry[sizeof(LDR_DATA_TABLE_ENTRY)];
	
	//read first LDR linked list 
	
	ReadProcessMemory(
		ProcessHandle,
		peb.Ldr,
		&LdrData,
		sizeof(LdrData),
		NULL);
	
	
	//read LDR entry
	ReadProcessMemory(
		ProcessHandle,
		LdrData.InMemoryOrderModuleList.Flink,
		LdrTableEntry,
		sizeof(LdrTableEntry) - sizeof(PVOID) * 2,
		NULL
	);
	
	ADDRESS DllBase = 0;
    ADDRESS DllName = 0;

	for(;;)
	{
		MEMCOPY(&DllBase, LdrTableEntry + sizeof(PVOID) * 4, sizeof(DllBase));
	
		if((LPVOID)DllBase == NULL) break;
        ADDRESS Flink = 0;
        MEMCOPY(&Flink, LdrTableEntry, sizeof(Flink));

        DllName = (ADDRESS)Flink;
#ifdef _WIN64
        DllName += (sizeof(PVOID) * 4 + sizeof(PVOID) * 5 + (sizeof(USHORT) * 2) * 2);
#else
        DllName += (sizeof(PVOID) * 4 + sizeof(PVOID) * 5 + sizeof(USHORT) * 2);
#endif // _WIN64

		ReadProcessMemory(
			ProcessHandle,
			(LPVOID)Flink, 
			LdrTableEntry,
			sizeof(LdrTableEntry) - sizeof(PVOID) * 2,
			NULL
		);
	
		if(Index == 0) break;
		Index -= 1;
	}

    ReadProcessMemory(
        ProcessHandle,
        (LPVOID)DllName,
        LdrTableEntry,
        sizeof(LdrTableEntry) - sizeof(PVOID) * 2,
        NULL
    );
	return DllBase;
}


ADDRESS GetRemoteProcessModuleInformation(HANDLE ProcessHandle, DWORD Index)
{
    PROCESS_BASIC_INFORMATION ProcessInformation;

    LPFN_NTQUERYPROCESSINFORMATION LPFN(NtQueryInformationProcess);

    LPFN(NtQueryInformationProcess) = (LPFN_NTQUERYPROCESSINFORMATION)GetProcedureAddress(
        GetModuleAddress("ntdll.dll"),
        "NtQueryInformationProcess"
    );

    // printf("\n");
    // printf("ntdll!NtQueryInformationProcess:%p\n", LPFN(NtQueryInformationProcess));

    ULONG ReturnLength = 0;
    NTSTATUS ReturnError = LPFN(NtQueryInformationProcess)(
        ProcessHandle,
        ProcessBasicInformation,
        &ProcessInformation,
        sizeof(ProcessInformation),
        &ReturnLength
        );

    // printf("PEB:\t\t\t\t%p\n", ProcessInformation.PebBaseAddress);

    PEB peb;
    ReadProcessMemory(
        ProcessHandle,
        ProcessInformation.PebBaseAddress,
        &peb,
        sizeof(peb),
        NULL
    );

    // printf("Loaded Information:\t\t%p\n", peb.Ldr);

    PEB_LDR_DATA LdrData;
    BYTE LdrTableEntry[sizeof(LDR_DATA_TABLE_ENTRY)];

    //read first LDR linked list 

    ReadProcessMemory(
        ProcessHandle,
        peb.Ldr,
        &LdrData,
        sizeof(LdrData),
        NULL);


    //read LDR entry
    ReadProcessMemory(
        ProcessHandle,
        LdrData.InMemoryOrderModuleList.Flink,
        LdrTableEntry,
        sizeof(LdrTableEntry) - sizeof(PVOID) * 2,
        NULL
    );

    ADDRESS DllBase = 0;

    for (;;)
    {
        MEMCOPY(&DllBase, LdrTableEntry + sizeof(PVOID) * 4, sizeof(DllBase));

        if ((LPVOID)DllBase == NULL) break;

        // printf("DllBase: \t\t\t%p\n", DllBase);

        ADDRESS Flink = 0;
        MEMCOPY(&Flink, LdrTableEntry, sizeof(Flink));

        ReadProcessMemory(
            ProcessHandle,
            (LPVOID)Flink,
            LdrTableEntry,
            sizeof(LdrTableEntry) - sizeof(PVOID) * 2,
            NULL
        );

        if (Index == 0) break;
        Index -= 1;
    }

    return DllBase;
}

LPVOID PEBStartup()
{
    #ifdef _WIN64
    BYTE GetPEBData[] = {0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0xc3};
    #else
    BYTE GetPEBData[] = {0x64, 0xa1, 0x30, 0x00, 0x00, 0x00, 0xC3};
    #endif

	LPBYTE fnGetPEB = (LPBYTE)VirtualAlloc(NULL, sizeof(GetPEBData), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    for(int i = 0; i != sizeof(GetPEBData); i++)
    {
        fnGetPEB[i] = GetPEBData[i];
    }

    GetPEB = (LPFN_GETPEB)fnGetPEB;
    return fnGetPEB; 
}

#endif