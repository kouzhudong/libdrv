#include "pch.h"


UNICODE_STRING g_kernel32 = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\kernel32.dll");
wchar_t g_Ntkernel32[MAX_PATH] = {0};
UNICODE_STRING g_Ntkernel32Path = {0};
wchar_t g_DosKernel32[MAX_PATH] = {0};
UNICODE_STRING g_DosKernel32Path = {0};

UNICODE_STRING g_kernelWow64 = RTL_CONSTANT_STRING(L"\\SystemRoot\\SysWOW64\\kernel32.dll");
wchar_t g_NtkernelWow64[MAX_PATH] = {0};
UNICODE_STRING g_NtkernelWow64Path = {0};
wchar_t g_DosKernelWow64[MAX_PATH] = {0};
UNICODE_STRING g_DosKernelWow64Path = {0};


//////////////////////////////////////////////////////////////////////////////////////////////////


void GetKernel32FullPath()
{
    RtlInitUnicodeString(&g_Ntkernel32Path, g_Ntkernel32);
    g_Ntkernel32Path.MaximumLength = sizeof(g_Ntkernel32);
    RtlInitUnicodeString(&g_DosKernel32Path, g_DosKernel32);
    g_DosKernel32Path.MaximumLength = sizeof(g_DosKernel32);

    GetSystemRootPathName(&g_kernel32, &g_Ntkernel32Path, &g_DosKernel32Path);

#ifdef _WIN64
    RtlInitUnicodeString(&g_NtkernelWow64Path, g_NtkernelWow64);
    g_NtkernelWow64Path.MaximumLength = sizeof(g_NtkernelWow64);
    RtlInitUnicodeString(&g_DosKernelWow64Path, g_DosKernelWow64);
    g_DosKernelWow64Path.MaximumLength = sizeof(g_DosKernelWow64);

    GetSystemRootPathName(&g_kernelWow64, &g_NtkernelWow64Path, &g_DosKernelWow64Path);
#endif
}


PVOID GetLoadLibraryExWAddress(HANDLE UniqueProcess)
/*
���ܣ���ȡһ�����̵�LoadLibraryExW�����ĵ�ַ��

����������ڵ��ļ��ǣ�
L"\\SystemRoot\\System32\\kernel32.dll"
L"\\SystemRoot\\SysWOW64\\kernel32.dll"
*/
{
    PVOID UserRoutine = NULL;

    //����һ�Ĳ��ԡ�
    UserRoutine = GetUserFunctionAddress(UniqueProcess, g_Ntkernel32Path.Buffer, "LoadLibraryExW");
    if (!UserRoutine) {
    #ifdef _WIN64 //Ϊ�����API��ʱ��Ϊ�˼ӿ��ٶȣ�����ж��ǲ���WOW64����.
        UserRoutine = GetUserFunctionAddress(UniqueProcess, g_NtkernelWow64Path.Buffer, "LoadLibraryExW");
    #endif
    }

    //�������Ĳ��ԣ���֧��WOW64��
    UserRoutine = GetUserFunctionAddressByPeb(UniqueProcess, g_DosKernel32Path.Buffer, "LoadLibraryExW");
    if (!UserRoutine) {
    #ifdef _WIN64 //Ϊ�����API��ʱ��Ϊ�˼ӿ��ٶȣ�����ж��ǲ���WOW64����.
        UserRoutine = GetUserFunctionAddressByPeb(UniqueProcess, g_DosKernelWow64Path.Buffer, "LoadLibraryExW");
    #endif
    }

    return UserRoutine;
}


NTSTATUS GetPcrTest()
{
    NTSTATUS Status = STATUS_SUCCESS;
    PKPCR pkpcr;
    struct _KPRCB * Prcb;
    //DBGKD_GET_VERSION64 * pdgv;
    //PKDDEBUGGER_DATA64 pkdd;
    //char * p;

    KeSetSystemAffinityThread(1);
    pkpcr = KeGetPcr();
    KeRevertToUserAffinityThread();

    Prcb = KeGetPrcb(pkpcr);

    ////�����ӡ��ȡһЩû�е�������Ҫ����Ϣ������������
    //pdgv = pkpcr->KdVersionBlock;//��X64����������㡣

    ////pkdd = (PKDDEBUGGER_DATA64)((char *)pkpcr + sizeof(DBGKD_GET_VERSION64));
    //p = (char *)pdgv;
    //p += sizeof(DBGKD_GET_VERSION64);
    //pkdd = (PKDDEBUGGER_DATA64)p;     

    return Status;
}


void TestUseNoExecuteMemory()
{
    NTSTATUS Status = STATUS_SUCCESS;

    UseNoExecuteMemory();

    UNICODE_STRING DosPathName{};
    DosPathName.MaximumLength = MAX_PATH;
    Status = AllocateUnicodeString(&DosPathName);
    if (NT_SUCCESS(Status)) {
        FreeUnicodeString(&DosPathName);
    }

    PVOID p = ExAllocatePoolWithTag(NonPagedPool, MAX_PATH, TAG);
    if (p) {
        ExFreePoolWithTag(p, TAG);
    }
}
