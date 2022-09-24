#include "pch.h"
#include "thread.h"
#include "Process.h"
#include "ssdt.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS GetThreadStartAddress(_In_ HANDLE  ThreadId, _Inout_ PVOID * StartAddress)
/*
ȱ�㣺��ĳЩƽ̨������취��ȡ��ϵͳ�̵߳���ʼ��ַ��0����Windows 10�����еĶ��ܻ�ȡ����
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
                                   &kernelThreadHandle);//ע��Ҫ�رվ����  
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
    //ע�⣺Start Address kernel32!BaseThreadStartThunk (0x7c810729)
    //ע������Ͷ�ջ������ʾ�ĵ�ַ�ǲ�һ���ġ�

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

    //��ȡ��Ҫ���ڴ档
    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return Status;
    }
    ReturnLength *= 2;//��һ������0x9700���ڶ�������0x9750,���Գ���2.
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

    //ö�ٽ�����Ϣ��
    //�ж�ϵͳ���̵ĺõİ취�Ǻ�PEPROCESS PsInitialSystemProcess�Ƚϡ�
    for (it = ProcessInfo; /* it->NextEntryOffset != 0 */; /*it++*/) //ע�͵Ķ���������ģ�������ʾһ���ȣ����Ը�Ϊwhile��
    {
        //ö���߳���Ϣ��
        i = 0;
        ThreadInfo = (PSYSTEM_THREAD_INFORMATION)(it + 1); //it->TH;
        for (; i < it->NumberOfThreads; i++) {
            /*
            ע�⣺
            1.��ͬһ����ַ�ܶ���̵߳�������ر�����ϵͳ���̡�
            2.X64ϵͳ���е��̵߳�ַΪ0��.�о��������Ҫ����Ҫ���ǻ�ȡ��TID��
            */
            //KdPrint(("    TID:%d����PID:%d��StartAddress:%p.\r\n",
            //         ThreadInfo->ClientId.UniqueThread, 
            //         ThreadInfo->ClientId.UniqueProcess, 
            //         ThreadInfo->StartAddress));

            if (ThreadInfo->ClientId.UniqueProcess == ProcessId) {
                r++;
            }

            /*
            ���Ҷ��ԣ�psti <= ((char *)it + it->NextEntryOffset)
            */
            ThreadInfo = (PSYSTEM_THREAD_INFORMATION)((char *)ThreadInfo + sizeof(SYSTEM_THREAD_INFORMATION));
        }

        /*
        The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member.
        For the last item in the array, NextEntryOffset is 0.
        ժ�ԣ�http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx��
        ˵����NextEntryOffset��ֵ�ǲ��̶��ģ�������SYSTEM_PROCESS_INFORMATION�ṹ�Ĵ�С�����Բ��ܼ�һ���ṹ�Ĵ�С��������
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
ע���������ڵ��̻߳�����IRQL��
*/
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ExFreePool(Apc);

    PsTerminateSystemThread(STATUS_SUCCESS);
    //ע���������û���˳��ˡ���Ϊ�߳̽����ˡ��ڵ���״̬�����л�����Ǹ��ϵ�(nt!DebugService2)��
    //Ҳ����˵����Ĵ���Ͳ��������ˡ�����˵����������������˳��Ĵ��롣
}


NTSTATUS KillSystemThread(_In_ PETHREAD Thread)
{
    NTSTATUS status = STATUS_SUCCESS;
    PKAPC Apc;

    Apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), TAG);
    if (NULL == Apc) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(Apc,
                    Thread,                           //����ܹؼ���
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
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "��ȡZwTerminateThread�ĵ�ַʧ��");
        return STATUS_UNSUCCESSFUL;
    }

    //KernelMode/UserMode��ȡ�Ķ����ں˾�����������ã��Ҷ�����ɱ���̡߳�
    Status = ObOpenObjectByPointer(Thread,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   GENERIC_ALL,
                                   *PsThreadType,
                                   KernelMode,
                                   &kernelThreadHandle);//ע��Ҫ�رվ����  
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
���ܣ�ͨ�õ�ö���̵߳ĺ�����

ע�ͣ��ص��������سɹ�������ö�١�
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

    //��ȡ��Ҫ���ڴ档
    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return Status;
    }
    ReturnLength *= 2;//��һ������0x9700���ڶ�������0x9750,���Գ���2.
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

    //ö�ٽ�����Ϣ��
    //�ж�ϵͳ���̵ĺõİ취�Ǻ�PEPROCESS PsInitialSystemProcess�Ƚϡ�
    for (it = ProcessInfo; /* it->NextEntryOffset != 0 */; /*it++*/) //ע�͵Ķ���������ģ�������ʾһ���ȣ����Ը�Ϊwhile��
    {
        //KdPrint(("PID:%d\tNumberOfThreads:%d\tHandleCount:%d\n",
        //         it->UniqueProcessId, 
        //         it->NumberOfThreads, 
        //         it->HandleCount));

        if (UniqueProcessId == it->UniqueProcessId) {
            //ö���߳���Ϣ��
            for (i = 0, ThreadInfo = it->TH; i < it->NumberOfThreads; i++) {
                /*
                ע�⣺
                1.��ͬһ����ַ�ܶ���̵߳�������ر�����ϵͳ���̡�
                2.X64ϵͳ���е��̵߳�ַΪ0��.�о��������Ҫ����Ҫ���ǻ�ȡ��TID��
                */
                //KdPrint(("    TID:%d����PID:%d��StartAddress:%p\n", 
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
                ���Ҷ��ԣ�psti <= ((char *)it + it->NextEntryOffset)
                */
                ThreadInfo = (PSYSTEM_THREAD_INFORMATION)((char *)ThreadInfo + sizeof(SYSTEM_THREAD_INFORMATION));
            }
        }

        /*
        The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member.
        For the last item in the array, NextEntryOffset is 0.
        ժ�ԣ�http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx��
        ˵����NextEntryOffset��ֵ�ǲ��̶��ģ�������PSYSTEM_PROCESS_INFORMATION_EX�ṹ�Ĵ�С�����Բ��ܼ�һ���ṹ�Ĵ�С��������
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
���ܣ�ʶ���ǲ����߳�ע�롣

˵�������̵�����������һ���̶߳�����Զ���߳�ע��ķ�ʽ�����ġ�
      ΢���sysmon���߶��ǰ�����ϱ�Ϊ�߳�ע�롣
      ���ǣ������ų���������ν��������Ϊ���߳�ע�롣

Parameters
ProcessId
[in] The process ID of the process.

��Ȼ��ע�룬�����ϵ�����������ǰ���̺�Ŀ����̡�
��һ��������Ŀ�����
��ǰ������Ҫ����PsGetCurrentProcessId��ȡ��

���л������̴߳���֪ͨ�Ļص�����ʱ����
*/
{
    bool ret = false;

    if (PsGetCurrentProcessId() == ProcessId) {
        return ret;//�Լ����Լ������̵߳ķŹ���
    }

    INT ThreadNumbers = 0;
    NTSTATUS status = GetThreadNumbers(ProcessId, &ThreadNumbers);
    if (!NT_SUCCESS(status)) {
        return ret;
    }

    if (ThreadNumbers <= 1) {
        return ret;//�������̵ķŹ���
    }

    return true;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
