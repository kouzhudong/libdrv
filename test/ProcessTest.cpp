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


NTSTATUS WINAPI HandleAllKernelModule(ULONG  numberOfModules, 
                                      PAUX_MODULE_EXTENDED_INFO modules, 
                                      _In_opt_ PVOID Context
)
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


PVOID gLogThreadObj;
LONG gDriverUnloading = FALSE;//为TRUE时就不再接受各个消息了，包括网络和进程。


VOID SystemThreadInIdleProcess(__in PVOID  StartContext)
/*

*/
{
    UNREFERENCED_PARAMETER(StartContext);

    for (; ; ) {
        if (gDriverUnloading) {
            break;//注意驱动卸载时，还有记录没有被读取/写入的情况。
        }

        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, 
              "i am in pid = %d process", HandleToLong(PsGetCurrentProcessId()));

        Sleep(1000);
    }

    //ASSERT(gDriverUnloading);

    PsTerminateSystemThread(STATUS_SUCCESS);
}


void StopSystemThreadInIdleProcess()
{
    InterlockedIncrement(&gDriverUnloading);

    ASSERT(gLogThreadObj);
    KeWaitForSingleObject(gLogThreadObj, Executive, KernelMode, FALSE, NULL);
    ObDereferenceObject(gLogThreadObj);
}


void CreateSystemThreadInIdleProcess()
/*
革命尚未成功，同志仍需努力。
*/
{
    NTSTATUS status;
    HANDLE threadHandle;
    //HANDLE ProcessHandle = NULL;
    PKPCR pkpcr;
    struct _KPRCB * Prcb;
    
    /*
    0: kd> dt _KPRCB IdleThread
    nt!_KPRCB
    +0x018 IdleThread : Ptr64 _KTHREAD
    */
    int IdleThreadOffset = 0x018;

    /*
    0: kd> dt _kthread Process
    nt!_KTHREAD
    +0x220 Process : Ptr64 _KPROCESS
    */
    int ProcessOffsetInThread = 0x220;

    KeSetSystemAffinityThread(1);
    pkpcr = KeGetPcr();
    KeRevertToUserAffinityThread();

    Prcb = KeGetPrcb(pkpcr);

    PETHREAD IdleThread = (PETHREAD)((PCHAR)Prcb + IdleThreadOffset);
    IdleThread = *(PETHREAD *)IdleThread;
    //DBG_UNREFERENCED_LOCAL_VARIABLE(IdleThread);

    //PEPROCESS IdleProcess = PsGetThreadProcess(IdleThread);//得到的值是NULL。

//    PEPROCESS IdleProcess = NULL;
//#pragma warning(push)
//#pragma warning(disable:6387)//“_Param_(1)”可能是“0”: 这不符合函数“PsLookupProcessByProcessId”的规范。
//    status = PsLookupProcessByProcessId(0, &IdleProcess);//STATUS_INVALID_CID
//#pragma warning(pop)      
//    ASSERT(NT_SUCCESS(status));

    //HANDLE IdleProcessId = PsGetProcessId(IdleProcess);
    //ASSERT(0 == IdleProcessId);
    //DBG_UNREFERENCED_LOCAL_VARIABLE(IdleProcessId);

    PEPROCESS IdleProcess = (PEPROCESS)((PCHAR)IdleThread + ProcessOffsetInThread);
    IdleProcess = *(PEPROCESS *)IdleProcess;
    //DBG_UNREFERENCED_LOCAL_VARIABLE(IdleProcess);
    
    //status = ObOpenObjectByPointer(IdleProcess,
    //                               OBJ_KERNEL_HANDLE,
    //                               NULL,
    //                               GENERIC_READ,
    //                               *PsProcessType,
    //                               KernelMode,
    //                               &ProcessHandle);
    //ASSERT(NT_SUCCESS(status));//即使填写正确的Idle进程，也会返回STATUS_OBJECT_TYPE_MISMATCH。

    status = PsCreateSystemThread(&threadHandle,
                                  THREAD_ALL_ACCESS,
                                  NULL,
                                  NULL, //ProcessHandle,
                                  NULL, 
                                  SystemThreadInIdleProcess, 
                                  NULL);
    ASSERT(NT_SUCCESS(status));
    status = ObReferenceObjectByHandle(threadHandle, 0, NULL, KernelMode, &gLogThreadObj, NULL);
    ASSERT(NT_SUCCESS(status));
    ZwClose(threadHandle);
    
    //ZwClose(ProcessHandle);
    //ObDereferenceObject(IdleProcess);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
