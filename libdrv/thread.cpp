#include "pch.h"
#include "thread.h"
#include "Process.h"
#include "ssdt.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS GetThreadStartAddress(_In_ HANDLE  ThreadId, _Inout_ PVOID * StartAddress)
/*
缺点：在某些平台下这个办法获取的系统线程的起始地址是0，在Windows 10下所有的都能获取到。
*/
{
    HANDLE          kernelThreadHandle = NULL;
    PETHREAD        Thread = NULL;
    THREADINFOCLASS ThreadInformationClass = ThreadQuerySetWin32StartAddress;
    SIZE_T          ThreadInformation = 0;
    ULONG           ThreadInformationLength = sizeof(PVOID);
    ULONG           ReturnLength = 0;
    NTSTATUS        Status = STATUS_SUCCESS;

    Status = PsLookupThreadByThreadId(ThreadId, &Thread);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return Status;
    }

    Status = ObOpenObjectByPointer(Thread,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   GENERIC_READ,
                                   *PsThreadType,
                                   KernelMode,
                                   &kernelThreadHandle);//注意要关闭句柄。  
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        ObDereferenceObject(Thread);
        return Status;
    }

    Status = ZwQueryInformationThread(kernelThreadHandle,
                                      ThreadInformationClass,
                                      &ThreadInformation,
                                      ThreadInformationLength,
                                      &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
    }

    *StartAddress = (PVOID)ThreadInformation;
    //KdPrint(("ProcessId:%d, ThreadId:%d, Win32 Start Address:0x%p\n", ProcessId, ThreadId, ThreadInformation)); 
    //注意：Start Address kernel32!BaseThreadStartThunk (0x7c810729)
    //注意这个和堆栈的里显示的地址是不一样的。

    ObDereferenceObject(Thread);
    ZwClose(kernelThreadHandle);

    return Status;
}


NTSTATUS GetThreadNumbers(_In_ HANDLE  ProcessId, _Inout_ PINT thread_number)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SYSTEM_PROCESS_INFORMATION temp = {0};
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = &temp;
    PSYSTEM_PROCESS_INFORMATION it = 0;
    ULONG SystemInformationLength = 0;
    ULONG ReturnLength = 0;
    ULONG i = 0;
    PSYSTEM_THREAD_INFORMATION ThreadInfo = 0;
    int r = 0;

    //获取需要的内存。
    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return Status;
    }
    ReturnLength *= 2;//第一次需求0x9700，第二次需求0x9750,所以乘以2.
    SystemInformationLength = ReturnLength;
    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(PagedPool, ReturnLength, TAG);
    if (ProcessInfo == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return Status;
    }
    RtlZeroMemory(ProcessInfo, ReturnLength);

    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(ProcessInfo, TAG);
        return Status;
    }

    //枚举进程信息。
    //判定系统进程的好的办法是和PEPROCESS PsInitialSystemProcess比较。
    for (it = ProcessInfo; /* it->NextEntryOffset != 0 */; /*it++*/) //注释的都是有问题的，如少显示一个等，可以改为while。
    {
        //枚举线程信息。
        i = 0;
        ThreadInfo = (PSYSTEM_THREAD_INFORMATION)(it + 1); //it->TH;
        for (; i < it->NumberOfThreads; i++) {
            /*
            注意：
            1.有同一个地址跑多个线程的情况。特别是在系统进程。
            2.X64系统上有的线程地址为0等.感觉这个不重要，重要的是获取了TID。
            */
            //KdPrint(("    TID:%d属于PID:%d，StartAddress:%p.\r\n",
            //         ThreadInfo->ClientId.UniqueThread, 
            //         ThreadInfo->ClientId.UniqueProcess, 
            //         ThreadInfo->StartAddress));

            if (ThreadInfo->ClientId.UniqueProcess == ProcessId) {
                r++;
            }

            /*
            并且断言：psti <= ((char *)it + it->NextEntryOffset)
            */
            ThreadInfo = (PSYSTEM_THREAD_INFORMATION)((char *)ThreadInfo + sizeof(SYSTEM_THREAD_INFORMATION));
        }

        /*
        The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member.
        For the last item in the array, NextEntryOffset is 0.
        摘自：http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx。
        说明：NextEntryOffset的值是不固定的，更不是SYSTEM_PROCESS_INFORMATION结构的大小。所以不能加一个结构的大小来遍历。
        */

        if (it->NextEntryOffset == 0) {
            break;
        }

        it = (PSYSTEM_PROCESS_INFORMATION)((char *)it + it->NextEntryOffset);
    }

    ExFreePoolWithTag(ProcessInfo, TAG);

    *thread_number = r;

    return Status;//STATUS_SUCCESS
}


void ApcCallback(PKAPC Apc,
                 PKNORMAL_ROUTINE NormalRoutine,
                 PVOID NormalContext,
                 PVOID SystemArgument1,
                 PVOID SystemArgument2
)
/*
注意这里所在的线程环境和IRQL。
*/
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ExFreePool(Apc);

    PsTerminateSystemThread(STATUS_SUCCESS);
    //注意这里可能没有退出了。因为线程结束了。在调试状态下运行会出现那个断点(nt!DebugService2)。
    //也就是说下面的代码就不会运行了。就是说这个函数不会运行退出的代码。
}


NTSTATUS KillSystemThread(_In_ PETHREAD Thread)
{
    NTSTATUS status = STATUS_SUCCESS;
    PKAPC Apc;

    Apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), TAG);
    if (NULL == Apc) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(Apc,
                    Thread,                           //这个很关键。
                    OriginalApcEnvironment,
                    (PKKERNEL_ROUTINE)&ApcCallback,   // kernel-mode routine
                    0,                                // rundown routine
                    0,                                // user-mode routine
                    KernelMode,
                    (PVOID)(ULONG)1);

    KeInsertQueueApc(Apc, (PVOID)(ULONG)2, (PVOID)(ULONG)3, 0);

    return status;
}


NTSTATUS KillUserThread(_In_ PETHREAD Thread)
{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE   kernelThreadHandle = NULL;

    if (NULL == ZwTerminateThreadFn) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "获取ZwTerminateThread的地址失败");
        return STATUS_UNSUCCESSFUL;
    }

    //KernelMode/UserMode获取的都是内核句柄，都可以用，且都可以杀死线程。
    Status = ObOpenObjectByPointer(Thread,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   GENERIC_ALL,
                                   *PsThreadType,
                                   KernelMode,
                                   &kernelThreadHandle);//注意要关闭句柄。  
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return Status;
    }

    Status = ZwTerminateThreadFn(kernelThreadHandle, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
    }

    ZwClose(kernelThreadHandle);

    return Status;
}


NTSTATUS EnumThread(_In_ HANDLE UniqueProcessId, _In_ HandleThread CallBack, _In_opt_ PVOID Context)
/*
功能：通用的枚举线程的函数。

注释：回调函数返回成功，结束枚举。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SYSTEM_PROCESS_INFORMATION_EX buffer = {0};
    PSYSTEM_PROCESS_INFORMATION_EX ProcessInfo = &buffer;
    PSYSTEM_PROCESS_INFORMATION_EX it = 0;
    ULONG SystemInformationLength = 0;
    ULONG ReturnLength = 0;
    ULONG i = 0;
    PSYSTEM_THREAD_INFORMATION ThreadInfo = 0;

    //获取需要的内存。
    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return Status;
    }
    ReturnLength *= 2;//第一次需求0x9700，第二次需求0x9750,所以乘以2.
    SystemInformationLength = ReturnLength;
    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION_EX)ExAllocatePoolWithTag(NonPagedPool, ReturnLength, TAG);
    if (ProcessInfo == NULL) {
        KdPrint(("ExAllocatePoolWithTag fail with 0x%x\n", Status));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(ProcessInfo, ReturnLength);

    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(ProcessInfo, TAG);
        return Status;
    }

    //枚举进程信息。
    //判定系统进程的好的办法是和PEPROCESS PsInitialSystemProcess比较。
    for (it = ProcessInfo; /* it->NextEntryOffset != 0 */; /*it++*/) //注释的都是有问题的，如少显示一个等，可以改为while。
    {
        //KdPrint(("PID:%d\tNumberOfThreads:%d\tHandleCount:%d\n",
        //         it->UniqueProcessId, 
        //         it->NumberOfThreads, 
        //         it->HandleCount));

        if (UniqueProcessId == it->UniqueProcessId) {
            //枚举线程信息。
            for (i = 0, ThreadInfo = it->TH; i < it->NumberOfThreads; i++) {
                /*
                注意：
                1.有同一个地址跑多个线程的情况。特别是在系统进程。
                2.X64系统上有的线程地址为0等.感觉这个不重要，重要的是获取了TID。
                */
                //KdPrint(("    TID:%d属于PID:%d，StartAddress:%p\n", 
                //         ThreadInfo->ClientId.UniqueThread, 
                //         ThreadInfo->ClientId.UniqueProcess,
                //         ThreadInfo->StartAddress));

                //KdPrint(("    ThreadState:%d\n", ThreadInfo->ThreadState));

                if (CallBack) {
                    Status = CallBack(&ThreadInfo->ClientId, Context);
                    if (NT_SUCCESS(Status)) {
                        break;
                    }
                }

                /*
                并且断言：psti <= ((char *)it + it->NextEntryOffset)
                */
                ThreadInfo = (PSYSTEM_THREAD_INFORMATION)((char *)ThreadInfo + sizeof(SYSTEM_THREAD_INFORMATION));
            }
        }

        /*
        The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member.
        For the last item in the array, NextEntryOffset is 0.
        摘自：http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx。
        说明：NextEntryOffset的值是不固定的，更不是PSYSTEM_PROCESS_INFORMATION_EX结构的大小。所以不能加一个结构的大小来遍历。
        */

        if (it->NextEntryOffset == 0) {
            break;
        }

        it = (PSYSTEM_PROCESS_INFORMATION_EX)((char *)it + it->NextEntryOffset);
    }

    ExFreePoolWithTag(ProcessInfo, TAG);

    return Status;//STATUS_SUCCESS
}


bool IsRemoteThread(_In_ HANDLE ProcessId)
/*
功能：识别是不是线程注入。

说明：进程的启动，即第一个线程都是用远程线程注入的方式创建的。
      微软的sysmon工具都是把这个上报为线程注入。
      但是，这里排除掉，即所谓正常人认为的线程注入。

Parameters
ProcessId
[in] The process ID of the process.

既然是注入，必须关系到两个概念：当前进程和目标进程。
第一个参数即目标进程
当前进程需要调用PsGetCurrentProcessId获取。

运行环境：线程创建通知的回调创建时机。
*/
{
    bool ret = false;

    if (PsGetCurrentProcessId() == ProcessId) {
        return ret;//自己给自己创建线程的放过。
    }

    INT ThreadNumbers = 0;
    NTSTATUS status = GetThreadNumbers(ProcessId, &ThreadNumbers);
    if (!NT_SUCCESS(status)) {
        return ret;
    }

    if (ThreadNumbers <= 1) {
        return ret;//创建进程的放过。
    }

    return true;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
