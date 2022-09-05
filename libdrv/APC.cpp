#include "APC.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID PspQueueApcSpecialApc(IN PKAPC Apc,
                           IN PKNORMAL_ROUTINE * NormalRoutine,
                           IN PVOID * NormalContext,
                           IN PVOID * SystemArgument1,
                           IN PVOID * SystemArgument2
)
//摘自：\WRK-v1.2\base\ntos\ps\psctx.c
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ExFreePool(Apc);
}


//NTSYSAPI 
NTSTATUS NTAPI NtQueueApcThread(__in HANDLE ThreadHandle,
                                __in PPS_APC_ROUTINE ApcRoutine,
                                __in_opt PVOID ApcArgument1,
                                __in_opt PVOID ApcArgument2,
                                __in_opt PVOID ApcArgument3
)
/*
Routine Description:
    This function is used to queue a user-mode APC to the specified thread.
    The APC will fire when the specified thread does an alertable wait
Arguments:
    ThreadHandle - Supplies a handle to a thread object.
                   The caller must have THREAD_SET_CONTEXT access to the thread.
                   且这个句柄必须是内核态的句柄。
    ApcRoutine - Supplies the address of the APC routine to execute when the APC fires.
    ApcArgument1 - Supplies the first PVOID passed to the APC
    ApcArgument2 - Supplies the second PVOID passed to the APC
    ApcArgument3 - Supplies the third PVOID passed to the APC
Return Value:
    Returns an NT Status code indicating success or failure of the API

摘自：\WRK-v1.2\base\ntos\ps\psctx.c
稍微有修改。

与其获取NtQueueApcThread的地址，不如直接实现它，兼容性有待考虑。

注意内核代码中有的地方在这个函数调用前KeRaiseIrql(APC_LEVEL, &OldIrql);
使用后然后KeLowerIrql(OldIrql);

由此可见，这里没有检查线程的状态，也没有等待APC操作的完成。
因为APC可能永远不执行。
所以，这也许是微软不公开APC的原因。
但是，它是一个基本的机制，所以，它不能被移去。
*/
{
    PETHREAD Thread;
    NTSTATUS st;
    KPROCESSOR_MODE Mode;
    PKAPC Apc;

    PAGED_CODE();

    //Mode = ExGetPreviousMode();//KeGetPreviousMode
    Mode = KernelMode;

    st = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_CONTEXT, *PsThreadType, Mode, (PVOID *)&Thread, NULL);
    if (NT_SUCCESS(st)) {
        st = STATUS_SUCCESS;
        //if (PsIsSystemThread(Thread)) {//IS_SYSTEM_THREAD
        if (PsGetProcessId(PsInitialSystemProcess) == PsGetThreadProcess(Thread)) {
            st = STATUS_INVALID_HANDLE;
        } else {
            Apc = (PKAPC)ExAllocatePoolWithQuotaTag(static_cast<POOL_TYPE>(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE),
                                                    sizeof(*Apc),
                                                    TAG);
            if (Apc == NULL) {
                st = STATUS_NO_MEMORY;
            } else {
                KeInitializeApc(Apc,
                                Thread,//&Thread->Tcb
                                OriginalApcEnvironment,
                                PspQueueApcSpecialApc,
                                NULL,
                                (PKNORMAL_ROUTINE)ApcRoutine,
                                UserMode,
                                ApcArgument1);
                if (!KeInsertQueueApc(Apc, ApcArgument2, ApcArgument3, 0)) {
                    ExFreePool(Apc);
                    st = STATUS_UNSUCCESSFUL;
                }
            }
        }

        ObDereferenceObject(Thread);
    }

    return st;
}


NTSTATUS NTAPI NtQueueApcThreadEx(__in HANDLE ThreadHandle,
                                  __in PPS_APC_ROUTINE ApcRoutine,
                                  __in_opt PVOID ApcArgument1,
                                  __in_opt PVOID ApcArgument2,
                                  __in_opt PVOID ApcArgument3
)
/*
对NtQueueApcThread的封装。

第一个参数，是用户态的句柄，其实是tid.
*/
{
    PETHREAD Thread;
    NTSTATUS Status = PsLookupThreadByThreadId(ThreadHandle, &Thread);
    if (NT_SUCCESS(Status)) {
        if (PsIsSystemThread(Thread)) {
            Status = STATUS_INVALID_HANDLE;
        } else {
            HANDLE KernelHandle;
            Status = ObOpenObjectByPointer(Thread,
                                           OBJ_KERNEL_HANDLE,
                                           NULL,
                                           THREAD_ALERT,
                                           *PsThreadType,
                                           KernelMode,
                                           &KernelHandle);
            if (NT_SUCCESS(Status)) {
                Status = NtQueueApcThread(KernelHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
                if (!NT_SUCCESS(Status)) {
                    KdPrint(("Status:%#x.\n", Status));
                }

                ZwClose(KernelHandle);
            }
        }

        ObDereferenceObject(Thread);
    }

    return Status;
}


VOID BaseDispatchAPC(LPVOID lpApcArgument1, LPVOID lpApcArgument2, LPVOID lpApcArgument3)
//摘自：\win2k\trunk\private\windows\base\client\thread.c
//注意：这个函数应在用户空间。
{
    PAPCFUNC pfnAPC;
    ULONG_PTR dwData;

    UNREFERENCED_PARAMETER(lpApcArgument3);

    pfnAPC = (PAPCFUNC)lpApcArgument1;
    dwData = (ULONG_PTR)lpApcArgument2;
    (pfnAPC)(dwData);
}


//WINBASEAPI 
DWORD WINAPI QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData)
/*++
Routine Description:
    This function is used to queue a user-mode APC to the specified thread.
    The APC will fire when the specified thread does an alertable wait.
Arguments:
    pfnAPC - Supplies the address of the APC routine to execute when the APC fires.
    hHandle - Supplies a handle to a thread object.
              The caller must have THREAD_SET_CONTEXT access to the thread.
    dwData - Supplies a DWORD passed to the APC
Return Value:
    TRUE - The operations was successful
    FALSE - The operation failed. GetLastError() is not defined.

摘自：\win2k\trunk\private\windows\base\client\thread.c
--*/
{
    NTSTATUS Status;

    Status = NtQueueApcThread(hThread, (PPS_APC_ROUTINE)BaseDispatchAPC, (PVOID)pfnAPC, (PVOID)dwData, NULL);
    if (!NT_SUCCESS(Status)) {
        return 0;
    }

    return 1;
}


VOID GetApcStateOffset(PSIZE_T ApcStateOffset)
/*
功能：获取ApcState在_kthread中的偏移。
代码和思路：http://www.rohitab.com/discuss/topic/40737-inject-dll-from-kernel-mode/

注意：还有几个成员，如：Alerted，Alertable等，不要混淆。
*/
{
    PEPROCESS Process = PsGetCurrentProcess();
    PETHREAD Thread = PsGetCurrentThread();
    PKAPC_STATE ApcState = NULL;
    SIZE_T * p = (SIZE_T *)Thread;
    int i = 0;

    // Locate the ApcState structure
    for (; i < 512; i++) {
        if (p[i] == (SIZE_T)Process) {
            ApcState = CONTAINING_RECORD(&p[i], KAPC_STATE, Process); // Get the actual address of KAPC_STATE
            *ApcStateOffset = (SIZE_T)ApcState - (SIZE_T)Thread; // Calculate the offset of the ApcState structure
            break;
        }
    }
}
