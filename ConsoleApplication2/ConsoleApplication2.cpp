#include <stdio.h>
#include <time.h>
#include <conio.h>

#include "./library/ADL/system/root.h"
#include "./library/ADL/system/memio.h"
#include "./library/ADL/system/ntdll.h"
#include "./library/ADL/system/kernel32.h"
#include "./library/ADL/system/memio.h"

//#define TIME_OUT_FLAG 
#define TIME_OUT 1000 * 10

typedef struct INTERCEPT_INFO
{
	ADDRESS* InterceptSymbol;
	ADDRESS* InterceptAddresses;
	BYTE* OriginalByte;
	DWORD Count;
}INTERCEPT_INFO;

BOOL CreateInt3(HANDLE ProcessHandle, ADDRESS Procedure, BYTE* OriginalByte)
{
	BYTE Int3 = 0xCC;
	ReadProcessMemory(ProcessHandle, (LPVOID)Procedure, OriginalByte, sizeof(BYTE), NULL);
	if (*OriginalByte == Int3) return FALSE;

	WriteProcessMemory(ProcessHandle, (LPVOID)Procedure, &Int3, sizeof(Int3), NULL);

	return TRUE;
}

BOOL CreateOriginalByte(HANDLE ProcessHandle, ADDRESS Procedure, BYTE* OriginalByte)
{
	BOOL error = WriteProcessMemory(ProcessHandle, (LPVOID)Procedure, OriginalByte, sizeof(*OriginalByte), NULL);

	return TRUE;
}

INTERCEPT_INFO InterceptProcedure(HANDLE ProcessHandle)
{
	// get module address

	ADDRESS NtDll = GetModuleAddress("ntdll");
	DWORD NumberOfProcedure = GetProcedureNumber(NtDll);

	INTERCEPT_INFO Info;
	Info.InterceptAddresses = (ADDRESS*)malloc((NumberOfProcedure + 1) * sizeof(ADDRESS));
	Info.InterceptSymbol = (ADDRESS*)malloc((NumberOfProcedure + 1) * sizeof(ADDRESS));
	Info.OriginalByte = (BYTE*)malloc((NumberOfProcedure + 1) * sizeof(BYTE));

	if (Info.InterceptAddresses == NULL ||
		Info.InterceptSymbol == NULL ||
		Info.OriginalByte == NULL)
	{
		fprintf(stdout, "failed to memory allocation!\n");

		ExitProcess(0);
	}

	/*
KiUserExceptionDispatcher
RtlDispatchException
NtContinue
NtRaiseException
RtlRaiseStatus
LdrInitializeThunk
NtTestAlert
RtlUserThreadStart
DbgUiRemoteBreakin
DbgBreakPoint
RtlExitUserThread
	*/
#define DENY_INDEX 11
	ADDRESS DenyProcedure[DENY_INDEX];
	DenyProcedure[0] = GetProcedureAddress(NtDll, "KiUserExceptionDispatcher");
	DenyProcedure[1] = GetProcedureAddress(NtDll, "RtlDispatchException");
	DenyProcedure[2] = GetProcedureAddress(NtDll, "NtContinue");
	DenyProcedure[3] = GetProcedureAddress(NtDll, "NtRaiseException");
	DenyProcedure[4] = GetProcedureAddress(NtDll, "RtlRaiseStatus");
	DenyProcedure[5] = GetProcedureAddress(NtDll, "LdrInitializeThunk");
	DenyProcedure[6] = GetProcedureAddress(NtDll, "NtTestAlert");
	DenyProcedure[7] = GetProcedureAddress(NtDll, "RtlUserThreadStart");
	DenyProcedure[8] = GetProcedureAddress(NtDll, "DbgUiRemoteBreakin");
	DenyProcedure[9] = GetProcedureAddress(NtDll, "DbgBreakPoint");
	DenyProcedure[10] = GetProcedureAddress(NtDll, "RtlExitUserThread");


	ADDRESS Procedure;
	ADDRESS Symbol;

	DWORD RegistedIndex = 0;
	DWORD ProcedureIndex = 0;

	MEMORY_BASIC_INFORMATION MemoryInfo;

	for (
		;
		ProcedureIndex != NumberOfProcedure;
		ProcedureIndex += 1
		)
	{
		BOOL Error = FALSE;
		Procedure = GetProcedureAddressFromIndex(NtDll, ProcedureIndex);
		Symbol = GetProcedureAddressNameFromIndex(NtDll, ProcedureIndex);

		for (int i = 0; i != DENY_INDEX; i++)
		{
			if (Procedure == DenyProcedure[i])
			{
				Error = TRUE;
				break;
			}
		}

		if (Error == FALSE)
		{
			Info.InterceptAddresses[RegistedIndex] = Procedure;
			Info.InterceptSymbol[RegistedIndex] = Symbol;

			CreateInt3(ProcessHandle, Info.InterceptAddresses[RegistedIndex], &Info.OriginalByte[RegistedIndex]);
			RegistedIndex += 1;
		}
	}

	Info.Count = RegistedIndex;

	return Info;
}

void UninterceptProcedure(HANDLE ProcessHandle, INTERCEPT_INFO Info)
{
	free(Info.InterceptAddresses);
	free(Info.InterceptSymbol);
	free(Info.OriginalByte);
}

#define STRING_FIND 1
#define STRING_COMPARE 2
int CompareCondition;

void DebuggeeEventHandler(HANDLE ProcessHandle, HANDLE ThreadHandle, const char* NameFinder, const char* NameSkiper, INTERCEPT_INFO Info)
{
	printf("[*] Option: %d\n", CompareCondition);
	printf("[*] Name Finder: %s\n", NameFinder);
	printf("[*] Name Skiper: %s\n", NameSkiper);

	DEBUG_EVENT DebugEvent;
	EXCEPTION_RECORD ExceptionRecord;
	MEMSET(&ExceptionRecord, 0, sizeof(ExceptionRecord));
	MEMORY_BASIC_INFORMATION MemoryInfo;

	clock_t FirstClock = clock();

	for (;;)
	{
		BOOL Error = FALSE;
		DWORD ContinueStatus = DBG_CONTINUE;

		WaitForDebugEvent(
			&DebugEvent,
			INFINITE);

		clock_t SecondClock = clock();

		EXCEPTION_RECORD ExceptionEvent = DebugEvent.u.Exception.ExceptionRecord;

		if (DebugEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
		{
			fprintf(stdout, "[*] Debbugger attach..\n");
		}

		if (DebugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
		{
			return;
		}

		if (EXCEPTION_DEBUG_EVENT == DebugEvent.dwDebugEventCode && ExceptionEvent.ExceptionCode == EXCEPTION_BREAKPOINT)
		{
			ExceptionRecord = DebugEvent.u.Exception.ExceptionRecord;

			for (DWORD i = 0; i != Info.Count; i += 1)
			{
				if (Info.InterceptAddresses[i] == (ADDRESS)ExceptionRecord.ExceptionAddress)
				{
					Error = TRUE;
					//create original byte
					CreateOriginalByte(
						ProcessHandle,
						Info.InterceptAddresses[i],
						&Info.OriginalByte[i]
					);

					CONTEXT Context;
					Context.ContextFlags = CONTEXT_ALL;

					HANDLE CurrentThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);

					GetThreadContext(CurrentThread, &Context);

					ADDRESS ReturnAddress = 0;
#ifdef _WIN64 
					Context.Rip -= 1;
					ADDRESS CallerPointer = Context.Rsp;
#else 
					Context.Eip -= 1;
					ADDRESS CallerPointer = Context.Esp;
#endif // _WIN64
					clock_t Print1 = clock();

					BOOL NameSearchError = FALSE;
					BOOL SkipSearchError = FALSE;
					const char* Name = NULL;

					ReadProcessMemory(ProcessHandle, (LPVOID)CallerPointer, &ReturnAddress, sizeof(ReturnAddress), NULL);

					if (NameFinder != NULL)
					{
						if (CompareCondition == STRING_COMPARE)
						{
							if (strcmp((const char*)Info.InterceptSymbol[i], NameFinder) != 0)
							{
								NameSearchError = TRUE;

								if ((Name = strstr((const char*)Info.InterceptSymbol[i], NameFinder)) == NULL)
								{
									NameSearchError = TRUE;

									if (NameSkiper != NULL)
									{
										if (strstr((const char*)Info.InterceptSymbol[i], NameSkiper) == NULL)
										{
											fprintf(stdout, "[RETN to %p] <= [CALL at %p]: %s\n", ReturnAddress, ExceptionRecord.ExceptionAddress, Info.InterceptSymbol[i]);
										}
									}
									else
									{
										fprintf(stdout, "[RETN to %p] <= [CALL at %p]: %s\n", ReturnAddress, ExceptionRecord.ExceptionAddress, Info.InterceptSymbol[i]);
									}
								}
							}
						}

						if (CompareCondition == STRING_FIND)
						{
							if ((Name = strstr((const char*)Info.InterceptSymbol[i], NameFinder)) != NULL)
							{
								NameSearchError = TRUE;

								if (NameSkiper != NULL)
								{
									if (strstr((const char*)Info.InterceptSymbol[i], NameSkiper) == NULL)
									{
										fprintf(stdout, "[RETN to %p] <= [CALL at %p]: %s\n", ReturnAddress, ExceptionRecord.ExceptionAddress, Info.InterceptSymbol[i]);
									}
								}
								else
								{
									fprintf(stdout, "[RETN to %p] <= [CALL at %p]: %s\n", ReturnAddress, ExceptionRecord.ExceptionAddress, Info.InterceptSymbol[i]);
								}
							}
						}
					}
					else
					{
						NameSearchError = TRUE;
					}

					SetThreadContext(CurrentThread, &Context);
					CloseHandle(CurrentThread);

					clock_t Print2 = clock();

					SecondClock -= Print2 - Print1;

					//exec
					ContinueDebugEvent(
						DebugEvent.dwProcessId,
						DebugEvent.dwThreadId,
						DBG_CONTINUE
					);
					Sleep(0);

					/*
					if (strcmp((const char*)Info.InterceptSymbol[i], "NtDeviceIoControlFile") == 0)
					{
						fprintf(stdout, "[+] Wait..\n");
						getchar();
					}
					*/

					//pause
					CreateInt3(
						ProcessHandle,
						Info.InterceptAddresses[i],
						&Info.OriginalByte[i]
					);
					Sleep(0);

					break;
				}
			}
		}

		if (Error == FALSE)
		{
			ContinueDebugEvent(
				DebugEvent.dwProcessId,
				DebugEvent.dwThreadId,
				DBG_CONTINUE
			);
		}

		//todo: time out..
#ifdef TIME_OUT_FLAG
		if (SecondClock - FirstClock > TIME_OUT) break;
#else
		Sleep(0);
#endif

	}

	return;
}

const char* ParamList[] = {
	"-find",
	"-compare",
	"-skip",
	"-view",
	"-save",
	"-open"
};

void QuitHandler(HANDLE* hProcess)
{
	_getch();

	TerminateProcess(*hProcess, 0);
}

int main(int argc, char** argv)
{
	PEBStartup();

	const char* ProcedureFindName = NULL;
	const char* ProcedureSkipName = NULL;

	char ExecuteCommand[MAX_PATH] = { 0, };

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOA si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = SW_SHOW;

	for (int i = 1; i != argc; i += 1)
	{
		for (int j = 0; j != (sizeof(ParamList) / sizeof(char*)); j += 1)
		{
			if (strcmp(argv[i], ParamList[j]) == 0)
			{
				if (i + 1 != argc)
				{
					if (strcmp(argv[i], "-find") == 0)
					{
						CompareCondition = STRING_FIND;
						ProcedureFindName = argv[i + 1];
					}

					if (strcmp(argv[i], "-compare") == 0)
					{
						CompareCondition = STRING_COMPARE;
						ProcedureFindName = argv[i + 1];
					}

					if (strcmp(argv[i], "-skip") == 0)
					{
						ProcedureSkipName = argv[i + 1];
					}

					if (strcmp(argv[i], "-open") == 0)
					{
						memcpy(ExecuteCommand, argv[i + 1], sizeof(ExecuteCommand));
					}
				}
			}
		}
	}

	if (CreateProcessA(NULL, ExecuteCommand, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		fprintf(stdout, "[*] Execute '%s'\n", ExecuteCommand);

		fprintf(stdout, "\n[*] Intercept module procedure\n");

		//debug init
		INTERCEPT_INFO Info = InterceptProcedure(pi.hProcess);
		ResumeThread(pi.hThread);

		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)QuitHandler, &pi.hProcess, 0, NULL);

		//active debug mode
		DebugActiveProcess(pi.dwProcessId);
		//start debug handler
		DebuggeeEventHandler(pi.hProcess, pi.hThread, ProcedureFindName, ProcedureSkipName, Info);

		//terminate
		UninterceptProcedure(pi.hProcess, Info);
		TerminateThread(pi.hThread, 0);
		fprintf(stdout, "[*] Debuggee is terminated..\n");
	}
	else
	{
		fprintf(stdout, "[!] Execute error '%s'\n", ExecuteCommand);
	}

	return 0;
}