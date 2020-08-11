#ifndef _NTDLL_H
#define _NTDLL_H

#include <windows.h>

//return type
typedef LONG NTSTATUS;
typedef LONG KPRIORITY;

//data query value
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

//process list structure


typedef enum _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
	DelayExecution = 4,
	Suspended = 5,
	UserRequest = 6,
	WrExecutive = 7,
	WrFreePage = 8,
	WrPageIn = 9,
	WrPoolAllocation = 10,
	WrDelayExecution = 11,
	WrSuspended = 12,
	WrUserRequest = 13,
	WrEventPair = 14,
	WrQueue = 15,
	WrLpcReceive = 16,
	WrLpcReply = 17,
	WrVirtualMemory = 18,
	WrPageOut = 19,
	WrRendezvous = 20,
	Spare2 = 21,
	Spare3 = 22,
	Spare4 = 23,
	Spare5 = 24,
	WrCalloutStack = 25,
	WrKernel = 26,
	WrResource = 27,
	WrPushLock = 28,
	WrMutex = 29,
	WrQuantumEnd = 30,
	WrDispatchInt = 31,
	WrPreempted = 32,
	WrYieldExecution = 33,
	WrFastMutex = 34,
	WrGuardedMutex = 35,
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _SYSTEM_THREAD
{
	/*000*/ FILETIME   ftKernelTime;   // 100 nsec units
	/*008*/ FILETIME   ftUserTime;    // 100 nsec units
	/*010*/ FILETIME   ftCreateTime;   // relative to 01-01-1601
	/*018*/ DWORD    dWaitTime;
	/*01C*/ PVOID    pStartAddress;
	/*020*/ CLIENT_ID  Cid;        // process/thread ids
	/*028*/ DWORD    dPriority;
	/*02C*/ DWORD    dBasePriority;
	/*030*/ DWORD    dContextSwitches;
	/*034*/ DWORD    dThreadState;   // 2=running, 5=waiting
	/*038*/ KWAIT_REASON WaitReason;
	/*03C*/ DWORD    dReserved01;
	/*040*/
}
SYSTEM_THREAD, * PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    //thread information?
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;
//data query API (export by ntdll)
//RTLGETNATIVESYSTEMFINFORMATION

typedef NTSTATUS(WINAPI *LPFN_NTQUERYSYSTEMINFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);


#endif