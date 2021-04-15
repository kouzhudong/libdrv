/*
������Ҫ����_SYSTEM_PROCESS_INFORMATION��

�Կ�SYSTEM_PROCESS_INFORMATION�Ķ����ж����֣�����΢�������ü�����
*/

#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
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
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


/*
�����ZwQuerySystemInformation�õĽṹ��
http://msdn.microsoft.com/en-us/library/windows/desktop/ms725506(v=vs.85).aspx
*/
//typedef struct _SYSTEM_PROCESS_INFORMATION {
//    ULONG NextEntryOffset;
//    ULONG NumberOfThreads;
//    BYTE Reserved1[48];
//    PVOID Reserved2[3];
//    HANDLE UniqueProcessId;
//    PVOID Reserved3;
//    ULONG HandleCount;
//    BYTE Reserved4[4];
//    PVOID Reserved5[11];
//    SIZE_T PeakPagefileUsage;
//    SIZE_T PrivatePageCount;
//    LARGE_INTEGER Reserved6[6];
//} SYSTEM_PROCESS_INFORMATION;


/*
һ�¶���ժ�ԣ�
C:\Program Files (x86)\Windows Kits\8.0\Include\um\winternl.h����
C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Include\winternl.h ����
http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx
ע�������NtQuerySystemInformation�õġ�
*/
//typedef struct _SYSTEM_PROCESS_INFORMATION {
//    ULONG NextEntryOffset;
//    BYTE Reserved1[52];
//    PVOID Reserved2[3];
//    HANDLE UniqueProcessId;
//    PVOID Reserved3;
//    ULONG HandleCount;
//    BYTE Reserved4[4];
//    PVOID Reserved5[11];
//    SIZE_T PeakPagefileUsage;
//    SIZE_T PrivatePageCount;
//    LARGE_INTEGER Reserved6[6];
//} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


//ժ�ԣ�WRK���ɼ�����û��SYSTEM_THREAD_INFORMATION��
//typedef struct _SYSTEM_PROCESS_INFORMATION {
//    ULONG NextEntryOffset;
//    ULONG NumberOfThreads;
//    LARGE_INTEGER SpareLi1;
//    LARGE_INTEGER SpareLi2;
//    LARGE_INTEGER SpareLi3;
//    LARGE_INTEGER CreateTime;
//    LARGE_INTEGER UserTime;
//    LARGE_INTEGER KernelTime;
//    UNICODE_STRING ImageName;
//    KPRIORITY BasePriority;
//    HANDLE UniqueProcessId;
//    HANDLE InheritedFromUniqueProcessId;
//    ULONG HandleCount;
//    ULONG SessionId;
//    ULONG_PTR PageDirectoryBase;
//    SIZE_T PeakVirtualSize;
//    SIZE_T VirtualSize;
//    ULONG PageFaultCount;
//    SIZE_T PeakWorkingSetSize;
//    SIZE_T WorkingSetSize;
//    SIZE_T QuotaPeakPagedPoolUsage;
//    SIZE_T QuotaPagedPoolUsage;
//    SIZE_T QuotaPeakNonPagedPoolUsage;
//    SIZE_T QuotaNonPagedPoolUsage;
//    SIZE_T PagefileUsage;
//    SIZE_T PeakPagefileUsage;
//    SIZE_T PrivatePageCount;
//    LARGE_INTEGER ReadOperationCount;
//    LARGE_INTEGER WriteOperationCount;
//    LARGE_INTEGER OtherOperationCount;
//    LARGE_INTEGER ReadTransferCount;
//    LARGE_INTEGER WriteTransferCount;
//    LARGE_INTEGER OtherTransferCount;
//
//    /*
//    ���������ǣ�
//    SYSTEM_THREAD_INFORMATION TH[1];
//    ����Ŀɲο���\win2k\private\windows\screg\winreg\perfdlls\os\perfsys.c��GetSystemThreadInfo������
//    */
//} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


/*
ժ�ԣ�http://doxygen.reactos.org/de/d22/ndk_2extypes_8h_source.html
*/
//typedef struct _SYSTEM_PROCESS_INFORMATION
//{
//    ULONG NextEntryOffset;
//    ULONG NumberOfThreads;
//    LARGE_INTEGER WorkingSetPrivateSize; //VISTA
//    ULONG HardFaultCount; //WIN7
//    ULONG NumberOfThreadsHighWatermark; //WIN7
//    ULONGLONG CycleTime; //WIN7
//    LARGE_INTEGER CreateTime;
//    LARGE_INTEGER UserTime;
//    LARGE_INTEGER KernelTime;
//    UNICODE_STRING ImageName;//������ֺ��񲻳���15-16���ַ���
//    KPRIORITY BasePriority;
//    HANDLE UniqueProcessId;
//    HANDLE InheritedFromUniqueProcessId;
//    ULONG HandleCount;
//    ULONG SessionId;
//    ULONG_PTR PageDirectoryBase;
//
//    //
//    // This part corresponds to VM_COUNTERS_EX.
//    // NOTE: *NOT* THE SAME AS VM_COUNTERS!
//    //
//    SIZE_T PeakVirtualSize;
//    SIZE_T VirtualSize;
//    ULONG PageFaultCount;
//    SIZE_T PeakWorkingSetSize;
//    SIZE_T WorkingSetSize;
//    SIZE_T QuotaPeakPagedPoolUsage;
//    SIZE_T QuotaPagedPoolUsage;
//    SIZE_T QuotaPeakNonPagedPoolUsage;
//    SIZE_T QuotaNonPagedPoolUsage;
//    SIZE_T PagefileUsage;
//    SIZE_T PeakPagefileUsage;
//    SIZE_T PrivatePageCount;
//
//    //
//    // This part corresponds to IO_COUNTERS
//    //
//    LARGE_INTEGER ReadOperationCount;
//    LARGE_INTEGER WriteOperationCount;
//    LARGE_INTEGER OtherOperationCount;
//    LARGE_INTEGER ReadTransferCount;
//    LARGE_INTEGER WriteTransferCount;
//    LARGE_INTEGER OtherTransferCount;
//    SYSTEM_THREAD_INFORMATION TH[1];//���������ע�͵��ġ�
//} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


//ժ�ԣ�http://doxygen.reactos.org/de/d22/ndk_2extypes_8h_source.html�����޸ġ�
//�����������ϸ���߳���Ϣ��
//typedef struct _SYSTEM_PROCESS_INFORMATION
//{
//    ULONG NextEntryOffset;
//    ULONG NumberOfThreads;
//    LARGE_INTEGER WorkingSetPrivateSize; //VISTA
//    ULONG HardFaultCount; //WIN7
//    ULONG NumberOfThreadsHighWatermark; //WIN7
//    ULONGLONG CycleTime; //WIN7
//    LARGE_INTEGER CreateTime;
//    LARGE_INTEGER UserTime;
//    LARGE_INTEGER KernelTime;
//    UNICODE_STRING ImageName;//������ֺ��񲻳���15-16���ַ���
//    KPRIORITY BasePriority;
//    HANDLE UniqueProcessId;
//    HANDLE InheritedFromUniqueProcessId;
//    ULONG HandleCount;
//    ULONG SessionId;
//    ULONG_PTR PageDirectoryBase;
//
//    //
//    // This part corresponds to VM_COUNTERS_EX.
//    // NOTE: *NOT* THE SAME AS VM_COUNTERS!
//    //
//    SIZE_T PeakVirtualSize;
//    SIZE_T VirtualSize;
//    ULONG PageFaultCount;
//    SIZE_T PeakWorkingSetSize;
//    SIZE_T WorkingSetSize;
//    SIZE_T QuotaPeakPagedPoolUsage;
//    SIZE_T QuotaPagedPoolUsage;
//    SIZE_T QuotaPeakNonPagedPoolUsage;
//    SIZE_T QuotaNonPagedPoolUsage;
//    SIZE_T PagefileUsage;
//    SIZE_T PeakPagefileUsage;
//    SIZE_T PrivatePageCount;
//
//    //
//    // This part corresponds to IO_COUNTERS
//    //
//    LARGE_INTEGER ReadOperationCount;
//    LARGE_INTEGER WriteOperationCount;
//    LARGE_INTEGER OtherOperationCount;
//    LARGE_INTEGER ReadTransferCount;
//    LARGE_INTEGER WriteTransferCount;
//    LARGE_INTEGER OtherTransferCount;
//    SYSTEM_THREAD_INFORMATION TH[1];//���������ע�͵��ġ�
//} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


//�����https://chromium.googlesource.com/chromium/chromium/+/1a9d8d9f3355e8b9f35591c8a678940bd264f412/third_party/psutil/psutil/arch/mswindows/ntextapi.h
//typedef struct _SYSTEM_PROCESS_INFORMATION
//{
//    ULONG NextEntryOffset;
//    ULONG NumberOfThreads;
//    LARGE_INTEGER SpareLi1;
//    LARGE_INTEGER SpareLi2;
//    LARGE_INTEGER SpareLi3;
//    LARGE_INTEGER CreateTime;
//    LARGE_INTEGER UserTime;
//    LARGE_INTEGER KernelTime;
//    UNICODE_STRING ImageName;
//    LONG BasePriority;
//    HANDLE UniqueProcessId;
//    HANDLE InheritedFromUniqueProcessId;
//    ULONG HandleCount;
//    ULONG SessionId;
//    ULONG_PTR PageDirectoryBase;
//    SIZE_T PeakVirtualSize;
//    SIZE_T VirtualSize;
//    ULONG PageFaultCount;
//    SIZE_T PeakWorkingSetSize;
//    SIZE_T WorkingSetSize;
//    SIZE_T QuotaPeakPagedPoolUsage;
//    SIZE_T QuotaPagedPoolUsage;
//    SIZE_T QuotaPeakNonPagedPoolUsage;
//    SIZE_T QuotaNonPagedPoolUsage;
//    SIZE_T PagefileUsage;
//    SIZE_T PeakPagefileUsage;
//    SIZE_T PrivatePageCount;
//    LARGE_INTEGER ReadOperationCount;
//    LARGE_INTEGER WriteOperationCount;
//    LARGE_INTEGER OtherOperationCount;
//    LARGE_INTEGER ReadTransferCount;
//    LARGE_INTEGER WriteTransferCount;
//    LARGE_INTEGER OtherTransferCount;
//    SYSTEM_THREAD_INFORMATION Threads[1];
//} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


//////////////////////////////////////////////////////////////////////////////////////////////////


//http://msdn.microsoft.com/en-us/library/cc248685.aspx
typedef struct _NT6_TS_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    //[size_is(MaximumLength/2), length_is(Length/2)] 
    PWSTR Buffer;
} NT6_TS_UNICODE_STRING;


/*
http://msdn.microsoft.com/en-us/library/cc248684.aspx
http://msdn.microsoft.com/en-us/library/cc248873.aspx ����allproc.h������WDK��WRK���涼û�У�ע��wdk8.1��û�а�װ��
*/
typedef struct _TS_SYS_PROCESS_INFORMATION_NT6 {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    NT6_TS_UNICODE_STRING ImageName;
    LONG BasePriority;
    DWORD UniqueProcessId;
    DWORD InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG SpareUl3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    ULONG PeakWorkingSetSize;
    ULONG WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;

    //����ṹ��SYSTEM_PROCESS_INFORMATION��࣬������������Щ��
} TS_SYS_PROCESS_INFORMATION_NT6, * PTS_SYS_PROCESS_INFORMATION_NT6;


//////////////////////////////////////////////////////////////////////////////////////////////////


//2008�汾��MSDN����WDK��
//http://msdn.microsoft.com/en-us/library/windows/desktop/ms687420(v=vs.85).aspx
//�����һЩ��ע�ڵͰ汾�ϵ�WDK����
EXTERN_C NTSTATUS /* WINAPI */ ZwQueryInformationProcess(
    __in          HANDLE ProcessHandle,
    __in          PROCESSINFOCLASS ProcessInformationClass,
    __out         PVOID ProcessInformation,
    __in          ULONG ProcessInformationLength,
    __out_opt     PULONG ReturnLength
);


//////////////////////////////////////////////////////////////////////////////////////////////////
