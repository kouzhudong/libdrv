#include "pch.h"
#include "RegistryTest.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


void RegisterLoadTest()
{
    UNICODE_STRING uRegistryPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\correy");

    //此文件必须是本计算机的,系统的或者自己生成的.
    UNICODE_STRING uRegDatPath = RTL_CONSTANT_STRING(L"\\DosDevices\\c:\\correy.DAT");

    OBJECT_ATTRIBUTES obj;
    OBJECT_ATTRIBUTES HiveFile;

    InitializeObjectAttributes(&obj, &uRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    InitializeObjectAttributes(&HiveFile, &uRegDatPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    ZwCreateRootKey(&obj, &HiveFile);
}


//////////////////////////////////////////////////////////////////////////////////////////////////
