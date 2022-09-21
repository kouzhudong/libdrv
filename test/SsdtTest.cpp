#include "pch.h"
#include "SsdtTest.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID GetZwTerminateThreadAddress()
{
    ZwTerminateThread_pfn ZwTerminateThread = (ZwTerminateThread_pfn)GetZwRoutineAddress("ZwTerminateThread");
    if (NULL == ZwTerminateThread) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "≤‚ ‘ ß∞‹");
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////
