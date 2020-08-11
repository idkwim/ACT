#ifndef _HOOKER_H
#define _HOOKER_H

#include "ADL.h"

#define ALREADY_HOOKED -1

int IsAlreadyHooked(HANDLE ProcessHandle, LPVOID API)
{
#ifdef _WIN64
	BYTE JmpInstruction[] = {0x48, 0xb8};
#else
	BYTE JmpInstruction[] = {0xb8};
#endif

	BYTE Code[sizeof(JmpInstruction)];

	VirtualRead(
		ProcessHandle,
		API,
		Code,
		sizeof(Code));

	if (Code[0] == JmpInstruction[0])
		return TRUE;

	return FALSE;
}

DWORD FindRet(LPVOID Procedure)
{
	LPBYTE bProcedure = (LPBYTE)Procedure;
	DWORD index = 0;

	for (; bProcedure[index] != 0xC3; index += 1)
		;

	return index + 1;
}

HOOK_INFO Hook(
	HANDLE ProcessId,
	LPVOID HookAddress,
	LPVOID Proc,
	LPVOID Arg,
	DWORD ArgSize)
{
	HOOK_INFO HookInfo;
	MEMSET(&HookInfo, 0, sizeof(HookInfo));

	CLIENT_ID ClientId = {
		0,
	};
	ClientId.UniqueProcess = ProcessId;
	OBJECT_ATTRIBUTES Object = {sizeof(Object)};

	HookInfo.Return = LPFN(NtOpenProcess)(
		&HookInfo.ProcessHandle,
		PROCESS_ALL_ACCESS,
		&Object,
		&ClientId);

	if (HookInfo.Return != 0)
		return HookInfo;

	BYTE Syscall[32];
	MEMSET(Syscall, 0, sizeof(Syscall));

	HookInfo.Hooker = HookAddress;

	HookInfo.Parameter = Arg;
	HookInfo.ParameterSize = ArgSize;

	HookInfo.Procedure = Proc;
	HookInfo.ProcedureSize = FindRet(Proc);

	HookInfo.Return = CreateVirtualHook(&HookInfo);

	if (HookInfo.Return != 0)
	{
		LPFN(NtClose)
		(HookInfo.ProcessHandle);
	}

	return HookInfo;
}


HOOK_INFO HookEx(
	HANDLE ProcessId,
	LPVOID HookAddress,
	LPVOID Proc,
	LPVOID Arg,
	DWORD ArgSize)
{
	HOOK_INFO HookInfo;
	MEMSET(&HookInfo, 0, sizeof(HookInfo));

	CLIENT_ID ClientId = {
		0,
	};
	ClientId.UniqueProcess = ProcessId;
	OBJECT_ATTRIBUTES Object = {sizeof(Object)};

	HookInfo.Return = LPFN(NtOpenProcess)(
		&HookInfo.ProcessHandle,
		PROCESS_ALL_ACCESS,
		&Object,
		&ClientId);

	if (HookInfo.Return != 0)
		return HookInfo;

	BYTE Syscall[32];
	MEMSET(Syscall, 0, sizeof(Syscall));

	HookInfo.Hooker = HookAddress;

	HookInfo.Parameter = Arg;
	HookInfo.ParameterSize = ArgSize;

	HookInfo.Procedure = Proc;
	HookInfo.ProcedureSize = FindRet(Proc);

	HookInfo.Return = CreateVirtualHook(&HookInfo);

	if (HookInfo.Return != 0)
	{
		LPFN(NtClose)
		(HookInfo.ProcessHandle);
	}

	return HookInfo;
}

#endif