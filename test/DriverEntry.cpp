#include "pch.h"
#include "DriverEntry.h"
#include "..\inc\lib.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID Unload(_In_ struct _DRIVER_OBJECT * DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();
}


EXTERN_C DRIVER_INITIALIZE DriverEntry;
//#pragma INITCODE
#pragma alloc_text(INIT, DriverEntry)
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(RegistryPath);

    if (!KD_DEBUGGER_NOT_PRESENT) {
        KdBreakPoint();//__debugbreak();
    }

    //if (*InitSafeBootMode) {
    //    return STATUS_ACCESS_DENIED;
    //}

    PAGED_CODE();

    DriverObject->DriverUnload = Unload;

    NetioEnumTest();

    return status;
}
