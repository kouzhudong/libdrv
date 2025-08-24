#pragma once


#include "pch.h"
#include "PEB.h"


//////////////////////////////////////////////////////////////////////////////////////////////////
/*
KLDR_DATA_TABLE_ENTRY的定义。
摘自：\nt5src\Source\Win2K3\NT\public\sdk\inc\ntldr.h

0: kd> vertarget
Windows 8 Kernel Version 9200 MP (8 procs) Free x64
Product: WinNt, suite: TerminalServer SingleUserTS
Built by: 19041.1.amd64fre.vb_release.191206-1406
Machine Name:
Kernel base = 0xfffff804`31400000 PsLoadedModuleList = 0xfffff804`3202a270
Debug session time: Sun Oct  9 20:20:53.225 2022 (UTC + 8:00)
System Uptime: 2 days 2:43:19.305
0: kd> dt _KLDR_DATA_TABLE_ENTRY
nt!_KLDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x010 ExceptionTable   : Ptr64 Void
   +0x018 ExceptionTableSize : Uint4B
   +0x020 GpValue          : Ptr64 Void
   +0x028 NonPagedDebugInfo : Ptr64 _NON_PAGED_DEBUG_INFO
   +0x030 DllBase          : Ptr64 Void
   +0x038 EntryPoint       : Ptr64 Void
   +0x040 SizeOfImage      : Uint4B
   +0x048 FullDllName      : _UNICODE_STRING
   +0x058 BaseDllName      : _UNICODE_STRING
   +0x068 Flags            : Uint4B
   +0x06c LoadCount        : Uint2B
   +0x06e u1               : <anonymous-tag>
   +0x070 SectionPointer   : Ptr64 Void
   +0x078 CheckSum         : Uint4B
   +0x07c CoverageSectionSize : Uint4B
   +0x080 CoverageSection  : Ptr64 Void
   +0x088 LoadedImports    : Ptr64 Void
   +0x090 Spare            : Ptr64 Void
   +0x098 SizeOfImageNotRounded : Uint4B
   +0x09c TimeDateStamp    : Uint4B
*/


typedef struct _KLDR_DATA_TABLE_ENTRY { //对比发现，和_LDR_DATA_TABLE_ENTRY在很多偏移上的成员的名字和类型都一样。
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    // ULONG padding on IA64
    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5; //名字不一样而已。
    PVOID SectionPointer;
    ULONG CheckSum; //从下面开始有变动。
    // ULONG padding on IA64
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;


typedef struct _KLDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;
    ULONG __Undefined1;
    ULONG __Undefined2;
    ULONG __Undefined3;
    ULONG NonPagedDebugInfo;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Undefined5;
    ULONG __Undefined6;
    ULONG CheckSum;
    ULONG TimeDateStamp;

    // NOTE : Do not grow this structure at the dump files used a packed array of these structures.
} KLDR_DATA_TABLE_ENTRY32, *PKLDR_DATA_TABLE_ENTRY32;


typedef struct _KLDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderLinks;
    ULONG64 __Undefined1;
    ULONG64 __Undefined2;
    ULONG64 __Undefined3;
    ULONG64 NonPagedDebugInfo;
    ULONG64 DllBase;
    ULONG64 EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Undefined5;
    ULONG64 __Undefined6;
    ULONG CheckSum;
    ULONG __padding1;
    ULONG TimeDateStamp;
    ULONG __padding2;

    // NOTE : Do not grow this structure at the dump files used a packed array of these structures.
} KLDR_DATA_TABLE_ENTRY64, *PKLDR_DATA_TABLE_ENTRY64;


//////////////////////////////////////////////////////////////////////////////////////////////////
//这些数据都是系统定义的，而不是自己定义的。


typedef struct _LDR_DATA_TABLE_ENTRY32 {//\WRK-v1.2\public\sdk\inc\ntldr.h
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY32 HashLinks;
        struct
        {
            ULONG SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct
        {
            ULONG TimeDateStamp;
        };
        struct
        {
            ULONG LoadedImports;
        };
    };

    // NOTE : Do not grow this structure at the dump files used a packed array of these structures.
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;


//\wrk\WindowsResearchKernel-WRK\WRK-v1.2\public\internal\base\inc\wow64t.h
#define TYPE32(x) ULONG
#define TYPE64(x) ULONGLONG


typedef struct _PEB_LDR_DATA32 {//WRK-v1.2\public\internal\base\inc\wow64t.h
    ULONG Length;
    BOOLEAN Initialized;
    TYPE32(HANDLE)
    SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    TYPE32(PVOID)
    EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;


typedef struct _WOW64_PROCESS {//摘自WRK的ps.h。
    PVOID Wow64;
} WOW64_PROCESS, *PWOW64_PROCESS;


/*
摘自：http://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx
*/
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


//https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
//typedef struct _LDR_DATA_TABLE_ENTRY
//{
//    LIST_ENTRY InLoadOrderLinks;
//    LIST_ENTRY InMemoryOrderLinks;
//    LIST_ENTRY InInitializationOrderLinks;
//    PVOID DllBase;
//    PVOID EntryPoint;
//    ULONG SizeOfImage;
//    UNICODE_STRING FullDllName;
//    UNICODE_STRING BaseDllName;
//    ULONG Flags;
//    WORD LoadCount;
//    WORD TlsIndex;
//    union
//    {
//        LIST_ENTRY HashLinks;
//        struct
//        {
//            PVOID SectionPointer;
//            ULONG CheckSum;
//        };
//    };
//    union
//    {
//        ULONG TimeDateStamp;
//        PVOID LoadedImports;
//    };
//    _ACTIVATION_CONTEXT * EntryPointActivationContext;
//    PVOID PatchInformation;
//    LIST_ENTRY ForwarderLinks;
//    LIST_ENTRY ServiceTagLinks;
//    LIST_ENTRY StaticLinks;
//} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _RTL_PROCESS_MODULE_INFORMATION {//WRK-v1.2\public\sdk\inc\ntldr.h
    HANDLE Section; // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256]; //注意结构对齐。发现这里的前四个字节应该是前面几个签名成员的值。
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;


typedef struct _RTL_PROCESS_MODULES {//WRK-v1.2\public\sdk\inc\ntldr.h
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _ImageContext {
    PWORK_QUEUE_ITEM Item;
    OUT NTSTATUS Status;

    OUT UNICODE_STRING ImageLoaded;

    IN HANDLE ProcessId;
    IN PUNICODE_STRING FullImageName;

    IN PIMAGE_INFO ImageInfo;
    IN PIMAGE_INFO_EX ImageInfoEx;
} ImageContext, *PImageContext;


typedef struct _LOAD_IMAGE_CONTEXT {
    WORK_QUEUE_ITEM hdr;
    ImageContext info;
    PKEVENT Event;
} LOAD_IMAGE_CONTEXT, *PLOAD_IMAGE_CONTEXT;


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef NTSTATUS(WINAPI * HandleKernelModule)(_In_ ULONG numberOfModules, _In_ PAUX_MODULE_EXTENDED_INFO ModuleInfo, _In_opt_ PVOID Context);
typedef NTSTATUS(WINAPI * HandleUserModule)(_In_ PVOID DllBase, _In_ PUNICODE_STRING FullDllName, _In_opt_ PVOID Context);
typedef NTSTATUS(NTAPI * HandleSection)(_In_ PVOID ViewBase, _In_ SIZE_T ViewSize, _In_opt_ PVOID Context);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


VOID EnumUserModule(_In_ HANDLE Pid, _In_opt_ HandleUserModule CallBack, _In_opt_ PVOID Context);

#if (NTDDI_VERSION >= NTDDI_VISTA)
PVOID GetNtBase();
PVOID GetImageBase(__in PCSTR name);
NTSTATUS EnumKernelModule(_In_ HandleKernelModule CallBack, _In_opt_ PVOID Context);
#endif

NTSTATUS ExtraFile(_In_ PCSTR FileName, _In_ ULONG_PTR Type, _In_ ULONG_PTR Id, _In_ PUNICODE_STRING NewFileName);

PVOID GetNtdllImageBase(PEPROCESS Process);

BOOLEAN MapViewOfSection(_In_ PUNICODE_STRING ImageFileName, _In_opt_ HandleSection CallBack, _In_opt_ PVOID Context);

NTSTATUS GetMemoryMappedFilenameInformation(_In_ HANDLE KernelProcessHandle,
                                            _In_opt_ PVOID DllBase,
                                            _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                                            _In_ SIZE_T MemoryInformationLength);

NTSTATUS ZwGetSystemModuleInformation();

VOID NTAPI RtlGetLoadImageFullName(_Inout_ PUNICODE_STRING LoadImageFullName,
                                   __in_opt PUNICODE_STRING FullImageName,
                                   __in HANDLE ProcessId,
                                   __in PIMAGE_INFO ImageInfo);

VOID NTAPI HideDriver(_In_ PDRIVER_OBJECT DriverObject);

EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
