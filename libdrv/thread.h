#pragma once


#include "pch.h"
#include "APC.h"
#include "TEB.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//摘自：http://msdn.microsoft.com/en-us/library/gg750724.aspx 这个WRK也有的。
typedef struct {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;


//https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
//typedef struct _SYSTEM_THREAD_INFORMATION {
//    LARGE_INTEGER Reserved1[3];
//    ULONG Reserved2;
//    PVOID StartAddress;
//    CLIENT_ID ClientId;
//    KPRIORITY Priority;
//    LONG BasePriority;
//    ULONG Reserved3;
//    ULONG ThreadState;
//    ULONG WaitReason;
//} SYSTEM_THREAD_INFORMATION;


/*
摘自：http://doxygen.reactos.org/de/d22/ndk_2extypes_8h_source.html

有修改：
1.最后一个成员反注释。
2.名字后加个EX
3.此目的是为了获取tid等信息。

感觉谷歌：
https://chromium.googlesource.com/chromium/chromium/+/1a9d8d9f3355e8b9f35591c8a678940bd264f412/third_party/psutil/psutil/arch/mswindows/ntextapi.h
的这个的定义也不错。
*/
typedef struct _SYSTEM_PROCESS_INFORMATION_EX
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; //VISTA
    ULONG HardFaultCount; //WIN7
    ULONG NumberOfThreadsHighWatermark; //WIN7
    ULONGLONG CycleTime; //WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;//这个名字好像不超过15-16个字符。
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;

    //
    // This part corresponds to VM_COUNTERS_EX.
    // NOTE: *NOT* THE SAME AS VM_COUNTERS!
    //
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;

    //
    // This part corresponds to IO_COUNTERS
    //
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION TH[1];//这个本来是注释掉的。
} SYSTEM_PROCESS_INFORMATION_EX, * PSYSTEM_PROCESS_INFORMATION_EX;


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef
NTSTATUS 
(WINAPI *ZwTerminateThread_pfn)(
    __in_opt HANDLE ThreadHandle,
    __in NTSTATUS ExitStatus
    );


//https://msdn.microsoft.com/en-us/library/windows/desktop/ms684283(v=vs.85).aspx
EXTERN_C NTSTATUS WINAPI ZwQueryInformationThread(
    _In_      HANDLE          ThreadHandle,
    _In_      THREADINFOCLASS ThreadInformationClass,
    _Inout_   PVOID           ThreadInformation,
    _In_      ULONG           ThreadInformationLength,
    _Out_opt_ PULONG          ReturnLength
);


//摘自：WRK。
EXTERN_C
BOOLEAN
PsIsThreadImpersonating(
    __in PETHREAD Thread
);


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef NTSTATUS(WINAPI * HandleThread) (_In_ PCLIENT_ID Cid, _In_opt_ PVOID Context);


EXTERN_C_START


NTSTATUS GetThreadStartAddress(_In_ HANDLE  ThreadId, _Inout_ PVOID * StartAddress);
NTSTATUS GetThreadNumbers(_In_ HANDLE  ProcessId, _Inout_ PINT thread_number);

NTSTATUS KillSystemThread(_In_ PETHREAD Thread);
NTSTATUS KillUserThread(_In_ PETHREAD Thread);

NTSTATUS EnumThread(_In_ HANDLE UniqueProcessId, _In_ HandleThread CallBack, _In_opt_ PVOID Context);

bool IsRemoteThread(_In_ HANDLE ProcessId);


EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
