/*
此文主要定义_SYSTEM_PROCESS_INFORMATION。

试看SYSTEM_PROCESS_INFORMATION的定义有多少种，仅仅微软都公开好几个。
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
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


/*
这个是ZwQuerySystemInformation用的结构。
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
一下定义摘自：
C:\Program Files (x86)\Windows Kits\8.0\Include\um\winternl.h或者
C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Include\winternl.h 或者
http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx
注意这个是NtQuerySystemInformation用的。
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


//摘自：WRK。可见里面没有SYSTEM_THREAD_INFORMATION。
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
//    这个后面就是：
//    SYSTEM_THREAD_INFORMATION TH[1];
//    具体的可参考：\win2k\private\windows\screg\winreg\perfdlls\os\perfsys.c的GetSystemThreadInfo函数。
//    */
//} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


/*
摘自：http://doxygen.reactos.org/de/d22/ndk_2extypes_8h_source.html
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
//    UNICODE_STRING ImageName;//这个名字好像不超过15-16个字符。
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
//    SYSTEM_THREAD_INFORMATION TH[1];//这个本来是注释掉的。
//} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


//摘自：http://doxygen.reactos.org/de/d22/ndk_2extypes_8h_source.html，有修改。
//这个包含更详细的线程信息。
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
//    UNICODE_STRING ImageName;//这个名字好像不超过15-16个字符。
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
//    SYSTEM_THREAD_INFORMATION TH[1];//这个本来是注释掉的。
//} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


//另见：https://chromium.googlesource.com/chromium/chromium/+/1a9d8d9f3355e8b9f35591c8a678940bd264f412/third_party/psutil/psutil/arch/mswindows/ntextapi.h
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
http://msdn.microsoft.com/en-us/library/cc248873.aspx 这是allproc.h，但是WDK和WRK里面都没有，注释wdk8.1我没有安装。
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

    //这个结构和SYSTEM_PROCESS_INFORMATION差不多，不过后面少了些。
} TS_SYS_PROCESS_INFORMATION_NT6, *PTS_SYS_PROCESS_INFORMATION_NT6;


//////////////////////////////////////////////////////////////////////////////////////////////////


//2008版本的MSDN，非WDK。
//http://msdn.microsoft.com/en-us/library/windows/desktop/ms687420(v=vs.85).aspx
//上面的一些标注在低版本上的WDK出错。
EXTERN_C NTSTATUS /* WINAPI */ ZwQueryInformationProcess(
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength);


//////////////////////////////////////////////////////////////////////////////////////////////////
