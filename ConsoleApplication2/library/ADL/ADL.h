/*
Anti ADS Library

project: CopyCat
programmer: woohyuk-seo
date: 2020-07-05
*/

#include <windows.h>

#include "./system/root.h"
#include "./system/ntdll.h"
#include "./system/kernel32.h"
#include "./system/memio.h"

#define GetVirtualProcedure(ModuleInfo, ProcedureName) GetProcedureAddress((ADDRESS)ModuleInfo.DllBase, ProcedureName)

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI *LPFN_NTOPENPROCESS)(
	PHANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId);

typedef NTSTATUS(WINAPI *LPFN_NTCLOSE)(
	HANDLE Handle);

typedef LPVOID(WINAPI *LPFN_VIRTUALALLOC)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect);

typedef BOOL(WINAPI *LPFN_VIRTUALFREE)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD dwFreeType);

typedef NTSTATUS(WINAPI *LPFN_NTWRITEVIRTUALMEMORY)(
	IN HANDLE ProcessHandle,
	OUT PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS(WINAPI *LPFN_NTREADVIRTUALMEMORY)(
	IN HANDLE ProcessHandle,
	OUT PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS(WINAPI *LPFN_NTALLOCATEVIRTUALMEMORY)(
	IN HANDLE ProcessHandle,
	OUT PVOID *BaseAddress,
	IN ULONG_PTR ZeroBits,
	OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

typedef NTSTATUS(WINAPI *LPFN_NTFREEVIRTUALMEMORY)(
	IN HANDLE ProcessHandle,
	OUT PVOID *BaseAddress,
	OUT PSIZE_T RegionSize,
	IN ULONG FreeType);

typedef NTSTATUS(WINAPI *LPFN_NTPROTECTVIRTUALMEMORY)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection);

typedef HANDLE (WINAPI *LPFN_CREATEFILEA)(
  	LPCSTR                lpFileName,
  	DWORD                 dwDesiredAccess,
  	DWORD                 dwShareMode,
  	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  	DWORD                 dwCreationDisposition,
  	DWORD                 dwFlagsAndAttributes,
  	HANDLE                hTemplateFile
);

typedef BOOL (WINAPI *LPFN_READFILE)(
  	HANDLE       hFile,
  	LPVOID       lpBuffer,
  	DWORD        nNumberOfBytesToRead,
  	LPDWORD      lpNumberOfBytesRead,
  	LPOVERLAPPED lpOverlapped
);

typedef BOOL (WINAPI *LPFN_CLOSEHANDLE)(
  	HANDLE       hFile
);

LPFN_VIRTUALALLOC LPFN(VirtualAlloc);
LPFN_VIRTUALFREE LPFN(VirtualFree);

LPFN_CREATEFILEA LPFN(CreateFileA);
LPFN_READFILE LPFN(ReadFile);
LPFN_CLOSEHANDLE LPFN(CloseHandle);

LPFN_NTOPENPROCESS LPFN(NtOpenProcess);
LPFN_NTCLOSE LPFN(NtClose);

LPFN_NTREADVIRTUALMEMORY LPFN(NtReadVirtualMemory);
LPFN_NTWRITEVIRTUALMEMORY LPFN(NtWriteVirtualMemory);

LPFN_NTALLOCATEVIRTUALMEMORY LPFN(NtAllocateVirtualMemory);
LPFN_NTFREEVIRTUALMEMORY LPFN(NtFreeVirtualMemory);

LPFN_NTPROTECTVIRTUALMEMORY LPFN(NtProtectVirtualMemory);

#include "CreateVirtualModule.h"

#include "./system/str.h"

typedef struct ADL_INFO
{
	MODULE_INFO nt_info;
	MODULE_INFO advapi_info;
	MODULE_INFO kernel32_info;
	LPVOID lpfn_peb_info;
} ADL_INFO;

ADL_INFO __ADL_GLOBAL_INFO__;

ADL_INFO ADLStartup()
{
	ADL_INFO info;

	info.lpfn_peb_info = PEBStartup();

	info.kernel32_info = CreateVirtualModule("kernel32.dll");
	LPFN(VirtualAlloc) = (LPFN_VIRTUALALLOC)GetVirtualProcedure(info.kernel32_info, "VirtualAlloc");
	LPFN(VirtualFree) = (LPFN_VIRTUALFREE)GetVirtualProcedure(info.kernel32_info, "VirtualFree");

	LPFN(CreateFileA) = (LPFN_CREATEFILEA)GetVirtualProcedure(info.kernel32_info, "CreateFileA");
	LPFN(ReadFile) = (LPFN_READFILE)GetVirtualProcedure(info.kernel32_info, "ReadFile");
	LPFN(CloseHandle) = (LPFN_CLOSEHANDLE)GetVirtualProcedure(info.kernel32_info, "CloseHandle");

	LPVOID LPFN(GetSystemWindowsDirectoryA) = (LPVOID)GetVirtualProcedure(info.kernel32_info, "GetSystemWindowsDirectoryA");

	char NtdllPath[MAX_PATH];
	char SystemDrive[32];
	((UINT (WINAPI *)(LPSTR, UINT))LPFN(GetSystemWindowsDirectoryA))(SystemDrive, sizeof(SystemDrive));

	_sprintf(NtdllPath, sizeof(NtdllPath), "%s/system32/ntdll.dll", SystemDrive);

	info.nt_info = CreateVirtualModuleEx(NtdllPath);
	LPFN(NtOpenProcess) = (LPFN_NTOPENPROCESS)GetVirtualProcedure(info.nt_info, "NtOpenProcess");
	LPFN(NtClose) = (LPFN_NTCLOSE)GetVirtualProcedure(info.nt_info, "NtClose");

	LPFN(NtWriteVirtualMemory) = (LPFN_NTWRITEVIRTUALMEMORY)GetVirtualProcedure(info.nt_info, "NtWriteVirtualMemory");
	LPFN(NtReadVirtualMemory) = (LPFN_NTREADVIRTUALMEMORY)GetVirtualProcedure(info.nt_info, "NtReadVirtualMemory");

	LPFN(NtAllocateVirtualMemory) = (LPFN_NTALLOCATEVIRTUALMEMORY)GetVirtualProcedure(info.nt_info, "NtAllocateVirtualMemory");
	LPFN(NtFreeVirtualMemory) = (LPFN_NTFREEVIRTUALMEMORY)GetVirtualProcedure(info.nt_info, "NtFreeVirtualMemory");
	LPFN(NtProtectVirtualMemory) = (LPFN_NTPROTECTVIRTUALMEMORY)GetVirtualProcedure(info.nt_info, "NtProtectVirtualMemory");

	__ADL_GLOBAL_INFO__ = info;

	return info;
}

void ADLCleanup(ADL_INFO VirtualModule)
{
	VirtualFree(VirtualModule.lpfn_peb_info, 0, MEM_RELEASE);
	FreeVirtualModule(VirtualModule.kernel32_info);
	FreeVirtualModule(VirtualModule.nt_info);
}

#include "process.h"