#pragma once


#include "pch.h"
#include "APC.h"
#include "TEB.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//ժ�ԣ�http://msdn.microsoft.com/en-us/library/gg750724.aspx ���WRKҲ�еġ�
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
ժ�ԣ�http://doxygen.reactos.org/de/d22/ndk_2extypes_8h_source.html

���޸ģ�
1.���һ����Ա��ע�͡�
2.���ֺ�Ӹ�EX
3.��Ŀ����Ϊ�˻�ȡtid����Ϣ��

�о��ȸ裺
https://chromium.googlesource.com/chromium/chromium/+/1a9d8d9f3355e8b9f35591c8a678940bd264f412/third_party/psutil/psutil/arch/mswindows/ntextapi.h
������Ķ���Ҳ����
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
    UNICODE_STRING ImageName;//������ֺ��񲻳���15-16���ַ���
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
    SYSTEM_THREAD_INFORMATION TH[1];//���������ע�͵��ġ�
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


//ժ�ԣ�WRK��
EXTERN_C
BOOLEAN
PsIsThreadImpersonating(
    __in PETHREAD Thread
);


//////////////////////////////////////////////////////////////////////////////////////////////////


//Win2K3\NT\base\published\winbase.w
typedef DWORD(WINAPI * PTHREAD_START_ROUTINE)(
    LPVOID lpThreadParameter
    );
typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;


//typedef DWORD(__stdcall * LPTHREAD_START_ROUTINE)(LPVOID lpThreadParameter);

//IDA
//NTSTATUS __stdcall RtlCreateUserThread(
//    HANDLE ProcessHandle,
//    PSECURITY_DESCRIPTOR SecurityDescriptor,
//    BOOLEAN CreateSuspended,
//    SIZE_T StackZeroBits,
//    SIZE_T StackReserve,
//    SIZE_T StackCommit,
//    PTHREAD_START_ROUTINE StartAddress,
//    PVOID Parameter,
//    PHANDLE ThreadHandle,
//    PCLIENT_ID ClientId);

//Win2K3\NT\public\sdk\inc\ntrtl.h
typedef NTSTATUS(*PUSER_THREAD_START_ROUTINE)(
    PVOID ThreadParameter
    );

//Win2K3\NT\base\ntos\rtl\rtlexec.c
//NTSTATUS NTAPI
//RtlCreateUserThread(
//    IN HANDLE Process,
//    IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
//    IN BOOLEAN CreateSuspended,
//    IN ULONG ZeroBits OPTIONAL,
//    IN SIZE_T MaximumStackSize OPTIONAL,
//    IN SIZE_T CommittedStackSize OPTIONAL,
//    IN PUSER_THREAD_START_ROUTINE StartAddress,
//    IN PVOID Parameter OPTIONAL,
//    OUT PHANDLE Thread OPTIONAL,
//    OUT PCLIENT_ID ClientId OPTIONAL
//);

//�˺����Ѿ����������Ǳ��뻷���������ƺ��ı���û��������塣
//ֻ����MmGetSystemRoutineAddress��ȡ���ɡ�
typedef
NTSTATUS (NTAPI *
RtlCreateUserThreadFn)(
    IN HANDLE Process,
    IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG ZeroBits OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN SIZE_T CommittedStackSize OPTIONAL,
    IN PUSER_THREAD_START_ROUTINE StartAddress,
    IN PVOID Parameter OPTIONAL,
    OUT PHANDLE Thread OPTIONAL,
    OUT PCLIENT_ID ClientId OPTIONAL
);

//Win2K3\NT\public\sdk\inc\ntrtl.h
//NTSYSAPI
//NTSTATUS
//NTAPI
//RtlCreateUserThread(
//    HANDLE Process,
//    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
//    BOOLEAN CreateSuspended,
//    ULONG StackZeroBits,
//    SIZE_T MaximumStackSize OPTIONAL,
//    SIZE_T InitialStackSize OPTIONAL,
//    PUSER_THREAD_START_ROUTINE StartAddress,
//    PVOID Parameter,
//    PHANDLE Thread,
//    PCLIENT_ID ClientId
//);


//////////////////////////////////////////////////////////////////////////////////////////////////
//NtCreateThreadEx��������������ģ�XPԴ����û�С�


/*
��ʵҲ�������NtCreateThreadEx��
��ΪRtlCreateUserThread->RtlpCreateUserThreadEx->ZwCreateThreadEx->NtCreateThreadEx��
����ZwCreateThreadEx��RtlCreateUserThread�ж���Ĺ��ܣ�����˵RtlCreateUserThreadɾ��ZwCreateThreadEx�Ĺ��ܡ�
��ʵRtlCreateUserThread��װ��ZwCreateThreadEx����ZwCreateThreadEx�����ø��Ѻá�
һ��ʹ��ZwCreateThreadEx��ԭ����RtlCreateUserThreadû�е���(win7�ϴ˺���û�е���)��
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef NTSTATUS(WINAPI * HandleThread) (_In_ PCLIENT_ID Cid, _In_opt_ PVOID Context);


extern volatile RtlCreateUserThreadFn RtlCreateUserThread;


EXTERN_C_START


NTSTATUS GetThreadStartAddress(_In_ HANDLE  ThreadId, _Inout_ PVOID * StartAddress);
NTSTATUS GetThreadNumbers(_In_ HANDLE  ProcessId, _Inout_ PINT thread_number);

NTSTATUS KillSystemThread(_In_ PETHREAD Thread);
NTSTATUS KillUserThread(_In_ PETHREAD Thread);

NTSTATUS EnumThread(_In_ HANDLE UniqueProcessId, _In_ HandleThread CallBack, _In_opt_ PVOID Context);

bool IsRemoteThread(_In_ HANDLE ProcessId);

NTSTATUS CreateUserThread(_In_ HANDLE Pid,
                          _In_ PUSER_THREAD_START_ROUTINE Function,
                          _In_ PVOID Parameter,
                          _Inout_ PHANDLE ThreadHandleReturn,
                          _Inout_ PCLIENT_ID ClientId
);


EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
