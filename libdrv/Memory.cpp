#include "Memory.h"
#include "Image.h"
#include "ssdt.h"
#include "Process.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS WINAPI EnumVirtualMemory(_In_ HANDLE Pid, _In_opt_ VirtualMemoryCallBack CallBack, _In_opt_ PVOID Context)
/*
功能：枚举一个进程的用户空间的内存。

调用此函数前，需先调用SetZwQueryVirtualMemoryAddress函数。
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    SIZE_T ReturnLength = {0};
    SIZE_T Address = NULL;//LPCVOID
    PEPROCESS Process = nullptr;
    HANDLE  KernelHandle = 0;

    if (NULL == ZwQueryVirtualMemoryFn) {
        return STATUS_UNSUCCESSFUL;
    }

    Status = PsLookupProcessByProcessId(Pid, &Process);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return Status;
    }

    Status = ObOpenObjectByPointer(Process, 
                                   OBJ_KERNEL_HANDLE, 
                                   NULL, 
                                   GENERIC_READ,
                                   *PsProcessType, 
                                   KernelMode,
                                   &KernelHandle);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ObDereferenceObject(Process);
        return Status;
    }

    SIZE_T HighestUserAddress = (SIZE_T)MmHighestUserAddress;
#if defined(_WIN64)
    if (PsGetProcessWow64Process(Process)) {
        HighestUserAddress = 0x7ffeffff;//32位的系统有3GB的配置，PE文件有大内存的配置，WOW64是否有3GB支持？
    } 
#endif

    for (; Address < HighestUserAddress;) {
        MEMORY_BASIC_INFORMATION MemoryBasicInfo = {0};
        Status = ZwQueryVirtualMemoryFn(KernelHandle,
                                        (PVOID)Address,
                                        MemoryBasicInformation,
                                        &MemoryBasicInfo,
                                        sizeof(MEMORY_BASIC_INFORMATION),
                                        &ReturnLength);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            //if (0 == MemoryBasicInfo.RegionSize) {
            //    Address += PAGE_SIZE;
            //}
            break;
        } else {
            if (CallBack) {
                Status = CallBack(Pid, &MemoryBasicInfo, Context);
                if (NT_SUCCESS(Status)) {
                    break;
                }
            }
        }

        Address += MemoryBasicInfo.RegionSize;
    }

    ZwClose(KernelHandle);
    ObDereferenceObject(Process);
    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void UseNoExecuteMemory()
/*
功能：禁止默认情况下使用可执行的内存。

有效范围：ExDefaultNonPagedPoolType和ExDefaultMdlProtection。对于别的可执行属性无效。

注释：不但对（静态）库有效，对使用的程序本身也有效。

建议：优先调用此函数。

用途：开启驱动程序校验器的断言处理。
*/
{
#if (NTDDI_VERSION >= NTDDI_VISTA)
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
#endif    
}
