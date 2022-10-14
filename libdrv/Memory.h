#pragma once

#include "pch.h"

class Memory
{

};


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
typedef struct _MEMORY_MAPPED_FILE_NAME_INFORMATION
{
    UNICODE_STRING Name;
    WCHAR     Buffer[_MAX_OBJECT_NAME];
} MEMORY_MAPPED_FILE_NAME_INFORMATION, * PMEMORY_MAPPED_FILE_NAME_INFORMATION;


//原型摘自：\Windows Kits\10\Include\10.0.19041.0\km\ntifs.h
//尽管\Windows Kits\10\Include\10.0.19041.0\km\ntifs.h加了(NTDDI_VERSION >= NTDDI_WIN2K)。
//但是早期的系统（XP）并没有导出这个函数。
//所以有此定义。
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


typedef NTSTATUS(WINAPI * VirtualMemoryCallBack)(_In_ HANDLE Pid,
                                                 _In_ PMEMORY_BASIC_INFORMATION MemoryBasicInfo,
                                                 _In_opt_ PVOID Context);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


NTSTATUS WINAPI EnumVirtualMemory(_In_ HANDLE Pid, _In_opt_ VirtualMemoryCallBack CallBack, _In_opt_ PVOID Context);

void UseNoExecuteMemory();


EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
