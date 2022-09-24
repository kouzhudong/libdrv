#include "pch.h"
#include "ProcessTest.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS WINAPI HandleVirtualMemory(_In_ HANDLE Pid,
                                    _In_ PMEMORY_BASIC_INFORMATION MemoryBasicInfo,
                                    _In_opt_ PVOID Context
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS Process = nullptr;
    HANDLE  KernelHandle = 0;

    //\nt4\private\sdktools\psapi\mapfile.c
    struct
    {
        OBJECT_NAME_INFORMATION ObjectNameInfo;
        WCHAR FileName[1024];//MAX_PATH 必须为1024，否则失败，原因看：ObQueryNameString。
    } s = {0};

    UNREFERENCED_PARAMETER(Context);    

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

    Status = GetMemoryMappedFilenameInformation(KernelHandle,
                                                MemoryBasicInfo->BaseAddress,
                                                &s.ObjectNameInfo,
                                                sizeof(s));
    if (NT_SUCCESS(Status)) {
        //Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "FullDllName:%wZ\n", &s.ObjectNameInfo.Name);
    }

    ZwClose(KernelHandle);
    ObDereferenceObject(Process);
    return STATUS_UNSUCCESSFUL;//继续枚举
}


NTSTATUS WINAPI HandleOneUserModule(_In_ PVOID DllBase, _In_ PUNICODE_STRING FullDllName, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(DllBase);
    UNREFERENCED_PARAMETER(FullDllName);
    UNREFERENCED_PARAMETER(Context);

    return STATUS_UNSUCCESSFUL;//继续枚举
}


NTSTATUS HandleOneThread(_In_ PCLIENT_ID Cid, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Cid);
    UNREFERENCED_PARAMETER(Context);

    return STATUS_UNSUCCESSFUL;//继续枚举
}


NTSTATUS WINAPI HandleOneProcess(HANDLE UniqueProcessId, _In_opt_ PVOID Context)
/*
测试样例：一个枚举进程的回调处理函数。
*/
{
    UNREFERENCED_PARAMETER(Context);

    EnumThread(UniqueProcessId, HandleOneThread, NULL);
    EnumUserModule(UniqueProcessId, HandleOneUserModule, NULL);
    EnumVirtualMemory(UniqueProcessId, HandleVirtualMemory, NULL);

    return STATUS_UNSUCCESSFUL;//继续枚举
}


NTSTATUS EnumProcessTest(VOID)
/*
测试用例：枚举进程的用法。
*/
{
    return EnumProcess(HandleOneProcess, NULL);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS WINAPI HandleAllKernelModule(ULONG  numberOfModules, PAUX_MODULE_EXTENDED_INFO modules, _In_opt_ PVOID Context)
/*
枚举内核模块（EnumAllKernelModule）的示例函数。

注释：此回调函数注册一次，调用一次。
*/
{
    UNREFERENCED_PARAMETER(Context);

    for (ULONG i = 0; i < numberOfModules; i++) {
        PUCHAR ModuleName = modules[i].FullPathName + modules[i].FileNameOffset;
        PVOID ImageBase = modules[i].BasicInfo.ImageBase;

    #if DBG 
        KdPrint(("ImageBase:%p, FullDllName:%s.\n", ImageBase, ModuleName));
    #else 
        DBG_UNREFERENCED_LOCAL_VARIABLE(ModuleName);
        DBG_UNREFERENCED_LOCAL_VARIABLE(ImageBase);
    #endif 
    }

    return STATUS_SUCCESS;
}


NTSTATUS PrintAllKernelModule()
/*
这是一个EnumAllKernelModule的用法的例子：枚举内核模块。
*/
{
    return EnumKernelModule(HandleAllKernelModule, NULL);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
