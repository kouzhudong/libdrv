#include "pch.h"
#include "RegistryTest.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void RegisterLoadTest()
{
    UNICODE_STRING uRegistryPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\correy");

    //���ļ������Ǳ��������,ϵͳ�Ļ����Լ����ɵ�.
    UNICODE_STRING uRegDatPath = RTL_CONSTANT_STRING(L"\\DosDevices\\c:\\correy.DAT");

    OBJECT_ATTRIBUTES obj;
    OBJECT_ATTRIBUTES HiveFile;

    InitializeObjectAttributes(&obj, &uRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    InitializeObjectAttributes(&HiveFile, &uRegDatPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    ZwCreateRootKey(&obj, &HiveFile);
}


void SetValueKeyDwordTest()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING WinDefend = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend");
    UNICODE_STRING WdFilter = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WdFilter");
    UNICODE_STRING Start = RTL_CONSTANT_STRING(L"Start");

    Status = SetValueKeyDword(&WinDefend, &Start, SERVICE_DISABLED);//�����ԣ�����ɹ���
    Status = SetValueKeyDword(&WdFilter, &Start, SERVICE_DISABLED); //�����ԣ������Ч��
}


//////////////////////////////////////////////////////////////////////////////////////////////////
