#pragma once

#include "pch.h"

class Memory
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef NTSTATUS(WINAPI * VirtualMemoryCallBack)(_In_ HANDLE Pid,
                                                 _In_ PMEMORY_BASIC_INFORMATION MemoryBasicInfo,
                                                 _In_opt_ PVOID Context);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START

NTSTATUS WINAPI EnumVirtualMemory(_In_ HANDLE Pid, _In_opt_ VirtualMemoryCallBack CallBack, _In_opt_ PVOID Context);

EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
