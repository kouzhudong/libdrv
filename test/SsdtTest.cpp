#include "pch.h"
#include "SsdtTest.h"

ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryFn;


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID GetZwTerminateThreadAddress()
{
    ZwTerminateThread_pfn ZwTerminateThread = (ZwTerminateThread_pfn)GetZwRoutineAddress("ZwTerminateThread");
    if (NULL == ZwTerminateThread) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "≤‚ ‘ ß∞‹");
    }
}


VOID GetSomeSystemRoutineAddress()
{
    //ZwTestAlert = (ZwTestAlertT)GetZwRoutineAddress("ZwTestAlert");
    //g_ZwQueueApcThread = (ZwQueueApcThreadT)GetZwRoutineAddress("ZwQueueApcThread");
    ZwQueryVirtualMemoryFn = (ZwQueryVirtualMemory_PFN)GetZwRoutineAddress("ZwQueryVirtualMemory");

    SetZwQueryVirtualMemoryAddress(ZwQueryVirtualMemoryFn);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
