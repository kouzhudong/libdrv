#include "pch.h"
#include "thread.h"
#include "Process.h"
#include "ssdt.h"

volatile RtlCreateUserThreadFn RtlCreateUserThread;


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
    NTSTATUS Status = STATUS_SUCCESS;
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

    return Status;
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
    NTSTATUS Status = GetThreadNumbers(ProcessId, &ThreadNumbers);
    if (!NT_SUCCESS(Status)) {
        return ret;
    }

    if (ThreadNumbers <= 1) {
        return ret;//�������̵ķŹ���
    }

    return true;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
//���º����д����ƺͲ��ԣ�����ֻ�Ǹ���˼·��ԭ�͡�


NTSTATUS
NTAPI
RtlpStartThread(
    PUSER_THREAD_START_ROUTINE Function,
    PVOID Parameter,
    HANDLE * ThreadHandleReturn
)
/*
ժ�ԣ�\Win2K3\NT\base\ntos\rtl\threads.c

ֻ���ο���ֱ��ʹ�ò�����ΪĿ����ע�롣
*/
{
    if (nullptr == RtlCreateUserThread) {
        return STATUS_UNSUCCESSFUL;
    }

    return RtlCreateUserThread(
        NtCurrentProcess(),     // process handle
        NULL,                   // security descriptor
        TRUE,                   // Create suspended?
        0L,                     // ZeroBits: default
        0L,                     // Max stack size: default
        0L,                     // Committed stack size: default
        Function,               // Function to start in
        Parameter,              // Parameter to start with
        ThreadHandleReturn,     // Thread handle return
        NULL                    // Thread id
    );
}


NTSTATUS CreateUserThread(_In_ HANDLE Pid, 
                          _In_ PUSER_THREAD_START_ROUTINE Function, 
                          _In_ PVOID Parameter,
                          _Inout_ PHANDLE ThreadHandleReturn,
                          _Inout_ PCLIENT_ID ClientId
)
/*
���ܣ�RtlCreateUserThread�ļ򵥷�װ��

������
1.Pid����ʵ��һ��������
2.Function��Ӧ�ò�Ĵ���ĵ�ַ��
3.Parameter��Ӧ�ò���ڴ��ַ��

ע�⣺���ô˺���֮ǰӦ���ȵ���SetRtlCreateUserThreadAddress��
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS  Process = nullptr;
    HANDLE  KernelHandle = nullptr;

    if (nullptr == ThreadHandleReturn || nullptr == ClientId) {
        return STATUS_UNSUCCESSFUL;
    }

    if (nullptr == RtlCreateUserThread) {
        return STATUS_UNSUCCESSFUL;
    }

    *ThreadHandleReturn = NULL;
    ClientId->UniqueProcess = NULL;
    ClientId->UniqueThread = NULL;

    __try {
        Status = PsLookupProcessByProcessId(Pid, &Process);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        Status = ObOpenObjectByPointer(Process,
                                       OBJ_KERNEL_HANDLE,
                                       NULL,
                                       GENERIC_ALL,
                                       *PsProcessType,
                                       KernelMode,
                                       &KernelHandle);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        Status = RtlCreateUserThread(
            KernelHandle,           // process handle �ں˾������Ӧ�ò��pid?�д�ʵ�顣
            NULL,                   // security descriptor
            FALSE,                  // Create suspended?
            0L,                     // ZeroBits: default
            0L,                     // Max stack size: default
            0L,                     // Committed stack size: default
            Function,               // Function to start in
            Parameter,              // Parameter to start with
            ThreadHandleReturn,    // Thread handle return
            ClientId               // Thread id
        );
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_INFO_LEVEL, "ThreadHandle:%p, UniqueThread:%p, UniqueProcess:%p",
                *ThreadHandleReturn, ClientId->UniqueThread, ClientId->UniqueProcess);
    } __finally {
        if (KernelHandle) {
            ZwClose(KernelHandle);
        }

        if (Process) {
            ObDereferenceObject(Process);
        }
    }

    return Status;
}


NTSTATUS CreateUserThreadEx(_In_ HANDLE Pid,
                            _In_ PUSER_THREAD_START_ROUTINE Function,
                            _In_ PVOID Parameter,
                            _Inout_ PHANDLE ThreadHandleReturn,
                            _Inout_ PCLIENT_ID ClientId
)
/*
���ܣ�ZwCreateThreadEx�ļ򵥷�װ��

������
1.Pid����ʵ��һ��������
2.Function��Ӧ�ò�Ĵ���ĵ�ַ��
3.Parameter��Ӧ�ò���ڴ��ַ��

ע�⣺���ô˺���֮ǰӦ���ȵ���SetZwCreateThreadExAddress��

����ԭ�ͱ�����CreateUserThread�߶ȼ��ݣ��о�PCLIENT_ID�����Ƕ���ġ�
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS Process = nullptr;
    HANDLE  KernelHandle = nullptr;

    if (nullptr == ThreadHandleReturn || nullptr == ClientId) {
        return STATUS_UNSUCCESSFUL;
    }

    if (nullptr == ZwCreateThreadEx) {
        return STATUS_UNSUCCESSFUL;
    }

    *ThreadHandleReturn = NULL;
    ClientId->UniqueProcess = NULL;
    ClientId->UniqueThread = NULL;

    __try {
        Status = PsLookupProcessByProcessId(Pid, &Process);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        Status = ObOpenObjectByPointer(Process,
                                       OBJ_KERNEL_HANDLE,
                                       NULL,
                                       GENERIC_ALL,
                                       *PsProcessType,
                                       KernelMode,
                                       &KernelHandle);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        //Status = RtlCreateUserThread(
        //    KernelHandle,           // process handle �ں˾������Ӧ�ò��pid?�д�ʵ�顣
        //    NULL,                   // security descriptor
        //    FALSE,                  // Create suspended?
        //    0L,                     // ZeroBits: default
        //    0L,                     // Max stack size: default
        //    0L,                     // Committed stack size: default
        //    Function,               // Function to start in
        //    Parameter,              // Parameter to start with
        //    ThreadHandleReturn,    // Thread handle return
        //    ClientId               // Thread id
        //);
        Status = ZwCreateThreadEx(ThreadHandleReturn,
                                  THREAD_ALL_ACCESS,
                                  NULL,
                                  KernelHandle,
                                  Function,
                                  Parameter,
                                  0,
                                  0,
                                  0,
                                  0,
                                  NULL);
        if (!NT_SUCCESS(Status) || nullptr == *ThreadHandleReturn) {
            PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        ClientId->UniqueProcess = Pid;

        PETHREAD Thread = nullptr;
        Status = ObReferenceObjectByHandle(*ThreadHandleReturn, 
                                           THREAD_ALL_ACCESS, 
                                           *PsThreadType, 
                                           KernelMode, 
                                           (PVOID *)&Thread,
                                           NULL);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        ClientId->UniqueThread = PsGetThreadId(Thread);

        ObDereferenceObject(Thread);
        //ZwClose(*ThreadHandleReturn);

        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_INFO_LEVEL, "ThreadHandle:%p, UniqueThread:%p, UniqueProcess:%p",
                *ThreadHandleReturn, ClientId->UniqueThread, Pid);
    } __finally {
        if (KernelHandle) {
            ZwClose(KernelHandle);
        }

        if (Process) {
            ObDereferenceObject(Process);
        }
    }

    return Status;
}


//NTSTATUS InjectDllByRtlCreateUserThread(HANDLE Process, LPCWSTR DllPullPath)
///*
//
//ע�⣺WOW64�Ĵ���
//"\\SystemRoot\\System32\\kernel32.dll"
//"\\SystemRoot\\SysWOW64\\kernel32.dll"
//
//��̾��
//��ô���ɺϡ�
//PUSER_THREAD_START_ROUTINE��LoadLibraryW��ԭ�;�Ȼһ�¡�
//���ԣ���ʡȥ����Ӧ�ò������ִ���ڴ�Ĳ�����
//��Ȼ������Ǹ��ƴ��루���Բ���shellcode����ȻҪ֧��WOW64����Ӧ�ò�Ĳ�����
//������˵shellcode�ˡ�
//
//ע�⣺WOW64�Ĳ����Ĵ�С���磺ָ���size_t�ȡ�
//
//DllPullPath���ڵ��ڴ���Ӧ�ò�ġ�
//*/
//{
//    NTSTATUS Status = STATUS_SUCCESS;
//    PUSER_THREAD_START_ROUTINE LoadLibraryW = nullptr;//LoadLibraryW�ĵ�ַ��
//
//    ASSERT(LoadLibraryW);
//
//    //Status = CreateUserThread(Process, LoadLibraryW, (PVOID)DllPullPath);
//
//    return Status;
//}


//////////////////////////////////////////////////////////////////////////////////////////////////
