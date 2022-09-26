#include "pch.h"
#include "SsdtTest.h"

ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryFn;


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID GetZwTerminateThreadAddress()
{
    ZwTerminateThread_pfn ZwTerminateThread = (ZwTerminateThread_pfn)GetZwRoutineAddress("ZwTerminateThread");
    if (NULL == ZwTerminateThread) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "����ʧ��");
    }
}


bool GetAndSetZwQueryVirtualMemoryAddress()
{
    if (nullptr != ZwQueryVirtualMemory) {//��ֱ�ӻ�ȡ�𣿣����������������ж��𣿣�
        ZwQueryVirtualMemoryFn = ZwQueryVirtualMemory;
    }

    if (!ZwQueryVirtualMemoryFn) {//��̬��ȡ�������ĺ�������
        UNICODE_STRING Temp = RTL_CONSTANT_STRING(L"ZwQueryVirtualMemory");
        ZwQueryVirtualMemoryFn = (ZwQueryVirtualMemory_PFN)MmGetSystemRoutineAddress(&Temp);
    }

    if (!ZwQueryVirtualMemoryFn) {//���Ͻ�ʧ�ܣ��Լ�����������ݣ��Լ���ȡ��
        ZwQueryVirtualMemoryFn = (ZwQueryVirtualMemory_PFN)GetZwRoutineAddress("ZwQueryVirtualMemory");
    }

    if (ZwQueryVirtualMemoryFn) {
        SetZwQueryVirtualMemoryAddress(ZwQueryVirtualMemoryFn);//���ڵ��þ�̬���һЩ������
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
