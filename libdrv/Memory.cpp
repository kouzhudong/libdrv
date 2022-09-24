#include "Memory.h"
#include "Image.h"
#include "ssdt.h"


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
        HighestUserAddress = 0x7ffeffff;
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
