#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


class SystemInfo
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
һ�¶���ժ�ԣ�
C:\Program Files (x86)\Windows Kits\8.0\Include\um\winternl.h����
C:\Program Files (x86)\Microsoft SDKs\Windows\v7.1A\Include\winternl.h

�������Ϣ���ɿ���
http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/System%20Information/SYSTEM_INFORMATION_CLASS.html#SystemProcessInformation
http://doxygen.reactos.org/d2/d5c/ntddk__ex_8h_source.html
*/
//typedef enum _SYSTEM_INFORMATION_CLASS {
//    SystemBasicInformation = 0,
//    SystemPerformanceInformation = 2,
//    SystemTimeOfDayInformation = 3,
//    SystemProcessInformation = 5,
//    SystemProcessorPerformanceInformation = 8,
//    SystemInterruptInformation = 23,
//    SystemExceptionInformation = 33,
//    SystemRegistryQuotaInformation = 37,
//    SystemLookasideInformation = 45
//} SYSTEM_INFORMATION_CLASS;


//����Ľṹժ��:http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/System%20Information/SYSTEM_INFORMATION_CLASS.html
//typedef enum _SYSTEM_INFORMATION_CLASS {
//    SystemBasicInformation,
//    SystemProcessorInformation,
//    SystemPerformanceInformation,
//    SystemTimeOfDayInformation,
//    SystemPathInformation,
//    SystemProcessInformation,
//    SystemCallCountInformation,
//    SystemDeviceInformation,
//    SystemProcessorPerformanceInformation,
//    SystemFlagsInformation,
//    SystemCallTimeInformation,
//    SystemModuleInformation,
//    SystemLocksInformation,
//    SystemStackTraceInformation,
//    SystemPagedPoolInformation,
//    SystemNonPagedPoolInformation,
//    SystemHandleInformation,
//    SystemObjectInformation,
//    SystemPageFileInformation,
//    SystemVdmInstemulInformation,
//    SystemVdmBopInformation,
//    SystemFileCacheInformation,
//    SystemPoolTagInformation,
//    SystemInterruptInformation,
//    SystemDpcBehaviorInformation,
//    SystemFullMemoryInformation,
//    SystemLoadGdiDriverInformation,
//    SystemUnloadGdiDriverInformation,
//    SystemTimeAdjustmentInformation,
//    SystemSummaryMemoryInformation,
//    SystemNextEventIdInformation,
//    SystemEventIdsInformation,
//    SystemCrashDumpInformation,
//    SystemExceptionInformation,
//    SystemCrashDumpStateInformation,
//    SystemKernelDebuggerInformation,
//    SystemContextSwitchInformation,
//    SystemRegistryQuotaInformation,
//    SystemExtendServiceTableInformation,
//    SystemPrioritySeperation,
//    SystemPlugPlayBusInformation,
//    SystemDockInformation,
//    SystemPowerInformation,//��ʾ�ظ�����,�����һ��1.
//    SystemProcessorSpeedInformation,
//    SystemCurrentTimeZoneInformation,
//    SystemLookasideInformation
//} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


//ժ�ԣ�\wrk\WindowsResearchKernel-WRK\WRK-v1.2\public\sdk\inc\ntexapi.h
// System Information Classes.
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,//ExpGetHandleInformation����ġ�
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
ժ�ԣ�http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx��
���޸ġ�
*/
EXTERN_C
NTSTATUS /* WINAPI NtQuerySystemInformation */ ZwQuerySystemInformation(
    _In_       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_    PVOID SystemInformation,
    _In_       ULONG SystemInformationLength,
    _Out_opt_  PULONG ReturnLength);


//�����ժ��:http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/System%20Information/NtQuerySystemInformation.html
//NTSYSAPI
//NTSTATUS
//NTAPI
//ZwQuerySystemInformation(//��Nt�޸�ΪZw.
//                         IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
//                         OUT PVOID               SystemInformation,
//                         IN ULONG                SystemInformationLength,
//                         OUT PULONG              ReturnLength OPTIONAL);


//https://msdn.microsoft.com/en-us/library/windows/desktop/ms725506%28v=vs.85%29.aspx
//EXTERN_C NTSTATUS WINAPI ZwQuerySystemInformation(
//    _In_       SYSTEM_INFORMATION_CLASS SystemInformationClass,
//    _Inout_    PVOID SystemInformation,
//    _In_       ULONG SystemInformationLength,
//    _Out_opt_  PULONG ReturnLength
//);


//////////////////////////////////////////////////////////////////////////////////////////////////
