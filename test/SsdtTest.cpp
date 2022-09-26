#include "pch.h"
#include "SsdtTest.h"

ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryFn;


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID GetZwTerminateThreadAddress()
{
    ZwTerminateThread_pfn ZwTerminateThread = (ZwTerminateThread_pfn)GetZwRoutineAddress("ZwTerminateThread");
    if (NULL == ZwTerminateThread) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "测试失败");
    }
}


bool GetAndSetZwQueryVirtualMemoryAddress()
{
    if (nullptr != ZwQueryVirtualMemory) {//能直接获取吗？（即：编译器环境有定吗？）
        ZwQueryVirtualMemoryFn = ZwQueryVirtualMemory;
    }

    if (!ZwQueryVirtualMemoryFn) {//动态获取（导出的函数）。
        UNICODE_STRING Temp = RTL_CONSTANT_STRING(L"ZwQueryVirtualMemory");
        ZwQueryVirtualMemoryFn = (ZwQueryVirtualMemory_PFN)MmGetSystemRoutineAddress(&Temp);
    }

    if (!ZwQueryVirtualMemoryFn) {//以上皆失败，自己解析相关数据，自己获取。
        ZwQueryVirtualMemoryFn = (ZwQueryVirtualMemory_PFN)GetZwRoutineAddress("ZwQueryVirtualMemory");
    }

    if (ZwQueryVirtualMemoryFn) {
        SetZwQueryVirtualMemoryAddress(ZwQueryVirtualMemoryFn);//便于调用静态库的一些函数。
    }

    return ZwQueryVirtualMemoryFn ? true : false;
}


VOID GetSomeSystemRoutineAddress()
{
    //ZwTestAlert = (ZwTestAlertT)GetZwRoutineAddress("ZwTestAlert");
    //g_ZwQueueApcThread = (ZwQueueApcThreadT)GetZwRoutineAddress("ZwQueueApcThread");
    
    GetAndSetZwQueryVirtualMemoryAddress();
}


//////////////////////////////////////////////////////////////////////////////////////////////////
