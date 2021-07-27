#pragma once


#include "pch.h"
#include "PEB.h"


//////////////////////////////////////////////////////////////////////////////////////////////////
//��Щ���ݶ���ϵͳ����ģ��������Լ�����ġ�


//\wrk\WindowsResearchKernel-WRK\WRK-v1.2\public\sdk\inc\ntldr.h
typedef struct _LDR_DATA_TABLE_ENTRY32
{
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
    union
    {
        LIST_ENTRY32 HashLinks;
        struct
        {
            ULONG SectionPointer;
            ULONG  CheckSum;
        };
    };
    union
    {
        struct
        {
            ULONG  TimeDateStamp;
        };
        struct
        {
            ULONG LoadedImports;
        };
    };

    // NOTE : Do not grow this structure at the dump files used a packed array of these structures.
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;


//\wrk\WindowsResearchKernel-WRK\WRK-v1.2\public\internal\base\inc\wow64t.h
#define TYPE32(x)   ULONG
#define TYPE64(x)   ULONGLONG


//\wrk\WindowsResearchKernel-WRK\WRK-v1.2\public\internal\base\inc\wow64t.h
typedef struct _PEB_LDR_DATA32
{
    ULONG Length;
    BOOLEAN Initialized;
    TYPE32(HANDLE) SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    TYPE32(PVOID) EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;


//ժ��WRK��ps.h��
typedef struct _WOW64_PROCESS
{
    PVOID Wow64;
} WOW64_PROCESS, * PWOW64_PROCESS;


/*
ժ�ԣ�http://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx
*/
typedef struct _LDR_DATA_TABLE_ENTRY
{
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union
    {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


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


#define DEVL TRUE 


//\WRK-v1.2\public\sdk\inc\ntmmapi.h
//typedef enum _MEMORY_INFORMATION_CLASS {
//    MemoryBasicInformation
//#if DEVL
//    , MemoryWorkingSetInformation
//#endif
//    , MemoryMappedFilenameInformation
//    , MemoryRegionInformation
//    , MemoryWorkingSetExInformation
//} MEMORY_INFORMATION_CLASS;
#define MemoryMappedFilenameInformation ((MEMORY_INFORMATION_CLASS)2)


#define _MAX_OBJECT_NAME 1024/sizeof(WCHAR)  
typedef struct _MEMORY_MAPPED_FILE_NAME_INFORMATION {
    UNICODE_STRING Name;
    WCHAR     Buffer[_MAX_OBJECT_NAME];
} MEMORY_MAPPED_FILE_NAME_INFORMATION, * PMEMORY_MAPPED_FILE_NAME_INFORMATION;


//ԭ��ժ�ԣ�\Windows Kits\10\Include\10.0.19041.0\km\ntifs.h
//����\Windows Kits\10\Include\10.0.19041.0\km\ntifs.h����(NTDDI_VERSION >= NTDDI_WIN2K)��
//�������ڵ�ϵͳ��XP����û�е������������
//�����д˶��塣
typedef
NTSTATUS
(NTAPI * ZwQueryVirtualMemory_PFN) (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );


//////////////////////////////////////////////////////////////////////////////////////////////////


//\WindowsResearchKernel-WRK\WRK-v1.2\public\sdk\inc\ntldr.h
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;                 // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];//ע��ṹ���롣���������ǰ�ĸ��ֽ�Ӧ����ǰ�漸��ǩ����Ա��ֵ��
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;


//\WindowsResearchKernel-WRK\WRK-v1.2\public\sdk\inc\ntldr.h
typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


//////////////////////////////////////////////////////////////////////////////////////////////////


#if defined(_WIN64)

//�������������XP-64�ϵ����ˡ�
EXTERN_C
//NTKERNELAPI
PVOID
PsGetProcessWow64Process(
    __in PEPROCESS Process
);

EXTERN_C
//NTKERNELAPI
PVOID
PsGetCurrentProcessWow64Process(
    VOID
);

#endif


/*
ժ�ԣ�\wrk\WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\inc\ps.h
�˺�����XP 32�Ͼ��Ѿ�������Ӧ�ÿ��Է���ʹ�á�
����ZwQueryInformationProcess �� ProcessBasicInformation.
*/
EXTERN_C
//NTKERNELAPI
PPEB
PsGetProcessPeb(
    __in PEPROCESS Process
);


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _ImageContext {
    PWORK_QUEUE_ITEM Item;
    OUT NTSTATUS status;

    OUT UNICODE_STRING ImageLoaded;

    IN HANDLE  ProcessId;
    IN PUNICODE_STRING  FullImageName;

    IN PIMAGE_INFO  ImageInfo;
    IN PIMAGE_INFO_EX ImageInfoEx;
}ImageContext, * PImageContext;


typedef struct _LOAD_IMAGE_CONTEXT {
    WORK_QUEUE_ITEM hdr;
    ImageContext info;
    PKEVENT Event;
}LOAD_IMAGE_CONTEXT, * PLOAD_IMAGE_CONTEXT;


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef NTSTATUS(WINAPI * HandleKernelModule)(_In_ ULONG numberOfModules,
                                              _In_ PAUX_MODULE_EXTENDED_INFO ModuleInfo,
                                              _In_opt_ PVOID Context);

typedef NTSTATUS(WINAPI * HandleUserModule)(_In_ PVOID DllBase,
                                            _In_ PUNICODE_STRING FullDllName,
                                            _In_opt_ PVOID Context);

typedef NTSTATUS(NTAPI * HandleSection)(_In_ PVOID ViewBase, _In_ SIZE_T ViewSize, _In_opt_ PVOID Context);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


VOID EnumUserModule(_In_ HANDLE Pid, _In_opt_ HandleUserModule CallBack, _In_opt_ PVOID Context);

#if (NTDDI_VERSION >= NTDDI_VISTA)
PVOID GetNtBase();
PVOID GetImageBase(__in PCSTR name);
NTSTATUS EnumKernelModule(_In_ HandleKernelModule CallBack, _In_opt_ PVOID Context);
#endif

BOOLEAN ExtraFile(_In_ PCSTR FileName,
                  _In_ ULONG_PTR Type,
                  _In_ ULONG_PTR Id,
                  _In_ PUNICODE_STRING NewFileName);

PVOID GetNtdllImageBase(PEPROCESS Process);

BOOLEAN MapViewOfSection(_In_ PUNICODE_STRING ImageFileName,
                         _In_opt_ HandleSection CallBack,
                         _In_opt_ PVOID Context);

NTSTATUS GetMemoryMappedFilenameInformation(_In_opt_ PVOID DllBase,
                                            _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                                            _In_ SIZE_T MemoryInformationLength);

NTSTATUS ZwGetSystemModuleInformation();

VOID NTAPI RtlGetLoadImageFullName(_Inout_ PUNICODE_STRING FileFullName,
                                   __in_opt PUNICODE_STRING  FullImageName,
                                   __in HANDLE  ProcessId,
                                   __in PIMAGE_INFO  ImageInfo);

EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
