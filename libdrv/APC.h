#pragma once


#include "pch.h"


class APC
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef
VOID
(*PKNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    );


//\WRK-v1.2\public\sdk\inc\ntpsapi.h
typedef VOID(*PPS_APC_ROUTINE) (__in_opt PVOID ApcArgument1,
                                __in_opt PVOID ApcArgument2,
                                __in_opt PVOID ApcArgument3);


//¸Ä×Ô£ºhttps://docs.microsoft.com/en-us/windows/win32/api/winnt/nc-winnt-papcfunc
typedef
void (*PAPCFUNC)(
    ULONG_PTR Parameter
    );


typedef
VOID
(*PKKERNEL_ROUTINE) (
    IN struct _KAPC * Apc,
    IN OUT PKNORMAL_ROUTINE * NormalRoutine,
    IN OUT PVOID * NormalContext,
    IN OUT PVOID * SystemArgument1,
    IN OUT PVOID * SystemArgument2
    );


typedef
VOID
(*PKRUNDOWN_ROUTINE) (
    IN struct _KAPC * Apc
    );


typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;


EXTERN_C
//NTKERNELAPI
VOID
KeInitializeApc(
    __out PRKAPC Apc,
    __in PRKTHREAD Thread,
    __in KAPC_ENVIRONMENT Environment,
    __in PKKERNEL_ROUTINE KernelRoutine,
    __in_opt PKRUNDOWN_ROUTINE RundownRoutine,
    __in_opt PKNORMAL_ROUTINE NormalRoutine,
    __in_opt KPROCESSOR_MODE ProcessorMode,
    __in_opt PVOID NormalContext
);


EXTERN_C
PLIST_ENTRY
KeFlushQueueApc(
    __inout PKTHREAD Thread,
    __in KPROCESSOR_MODE ProcessorMode
);


EXTERN_C
//NTKERNELAPI
BOOLEAN
KeInsertQueueApc(
    __inout PRKAPC Apc,
    __in_opt PVOID SystemArgument1,
    __in_opt PVOID SystemArgument2,
    __in KPRIORITY Increment
);


EXTERN_C BOOLEAN KeRemoveQueueApc(__inout PKAPC Apc);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


NTSTATUS NTAPI NtQueueApcThread(__in HANDLE ThreadHandle,
                                __in PPS_APC_ROUTINE ApcRoutine,
                                __in_opt PVOID ApcArgument1,
                                __in_opt PVOID ApcArgument2,
                                __in_opt PVOID ApcArgument3);

NTSTATUS NTAPI NtQueueApcThreadEx(__in HANDLE ThreadHandle,
                                  __in PPS_APC_ROUTINE ApcRoutine,
                                  __in_opt PVOID ApcArgument1,
                                  __in_opt PVOID ApcArgument2,
                                  __in_opt PVOID ApcArgument3);

VOID GetApcStateOffset(PSIZE_T ApcStateOffset);


EXTERN_C_END
