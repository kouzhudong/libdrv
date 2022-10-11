#include "pch.h"
#include "Image.h"
#include "Process.h"
#include "File.h"
#include "object.h"
#include "ssdt.h"


#pragma warning(disable:4366) //һԪ��&��������Ľ��������δ�����


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS GetMemoryMappedFilenameInformation(_In_ HANDLE KernelProcessHandle, 
                                            _In_opt_ PVOID DllBase,
                                            _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                                            _In_ SIZE_T MemoryInformationLength
)
/*
˵�����˺�����Ҫ���û���ȡӦ�ò����Ӧ��ַ��ӳ���ļ���ȫ·����

��ΪWOW64_PEB��ȡ��ImagePathName���ԣ���Ϊ����system32,���Ǿ��Բ��Եġ�
����Ӧ�ÿ϶�����Щ�ṹ����ȷ�ġ�
����ֻ����ΪImagePathName�����ˡ�

���Ǵ�ʱ�Ѿ���ȡ�ˣ�DllBase��SizeOfImage��BaseDllName��������Щ����ȷ�ġ�
ע�⣺NLS�ȷǳ����DLL�ǲ������ġ�

���������и�����Щ��ȡImagePathName������͹��ܡ�

MmGetFileNameForAddress����δ������������ʹ�á�
AuxKlibQueryModuleInformationֻ�ܻ�ȡ�ں˵ģ���RtlQueryModuleInformation�ķ�װ�������Ǳ�ķ�װ��
ZwQueryVirtualMemory MemoryMappedFilenameInformation MEMORY_MAPPED_FILE_NAME_INFORMATION

ZwQueryVirtualMemory����ȻWindows���ڲŹ��������������ǲ������ģ�����Ҫ��̬��ȡ��������ĵ�ַ��
����\Windows Kits\10\Include\10.0.19041.0\km\ntifs.h����(NTDDI_VERSION >= NTDDI_WIN2K)��

ZwQueryVirtualMemoryʹ���м���ע�����
1.�˺��������ڻص���ֱ�����У���WorkItemThread�����гɹ������߷���STATUS_ACCESS_VIOLATION��
2.��ʱ�ľ���������ں�̬�Ľ��̾����
3.�˺�������ҪAttachProcess����Ϊ�����н��̵ľ����
4.NtQueryVirtualMemory���н�ȥ������������������������ˣ���������ڲ�����������
  ֻ��һ�������̣߳�Ҳ����֣��������Լ��Ĺ����߳��Ŷ�Ҳ������ˡ�
5.�����һ��������NtCurrentProcess()��������KeStackAttachProcess��

�ο�������
MmGetFileNameForAddress
0: kd> x nt!RtlPcTo* �⼸������Ӧ�ý���֧���ں�ģ��
fffff804`65544fb0 nt!RtlPcToFileHeader (RtlPcToFileHeader)
fffff804`65b169e0 nt!RtlPcToFilePath (RtlPcToFilePath)
fffff804`655c95d0 nt!RtlPcToFileName (RtlPcToFileName)

���ô˺���ǰ���ȵ���SetZwQueryVirtualMemoryAddress������
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SIZE_T ReturnLength = {0};

    if (NULL == ZwQueryVirtualMemoryFn) {
        return Status;
    }

    Status = ZwQueryVirtualMemoryFn(KernelProcessHandle, //NtCurrentProcess(),
                                    DllBase,
                                    MemoryMappedFilenameInformation,
                                    MemoryInformation,
                                    MemoryInformationLength,
                                    &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        //Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
    } else {
        //KdPrint(("FullDllName:%wZ\n", &s.ObjectNameInfo.Name));
    }

    return Status;

    //////////////////////////////////////////////////////////////////////////////////////////////

    //PIMAGE_NT_HEADERS NtHeaders = NULL;
    //UNICODE_STRING Name = {0};

    //NtHeaders = RtlImageNtHeader ((PVOID)DllBase);
    //if (NtHeaders) 
    //{

    //}

    //Status = MmGetFileNameForAddress (NtHeaders, &Name);
    //if (NT_SUCCESS (Status))
    //{
    //    KdPrint(("FullDllName:%wZ\n", &Name)); 
    //    ExFreePool (Name.Buffer);
    //}  
}


#if defined(_WIN64)


void EnumWow64Module0(PWOW64_PROCESS pwp, _In_opt_ HandleUserModule CallBack, _In_opt_ PVOID Context)
/*
���ܣ�����һ��WOW64���̵�WOW64ģ�顣

�ο���WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\dbgk\dbgkobj.c��DbgkpPostFakeModuleMessages������
*/
{
    PPEB32 Peb32 = (PPEB32)pwp;
    PPEB_LDR_DATA32 Ldr32;
    PLIST_ENTRY32 LdrHead32, LdrNext32;
    PLDR_DATA_TABLE_ENTRY32 LdrEntry32;

    __try {
        Ldr32 = (PPEB_LDR_DATA32)UlongToPtr(Peb32->Ldr);
        LdrHead32 = &Ldr32->InLoadOrderModuleList;
        for (LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrHead32->Flink);
             LdrNext32 != LdrHead32;
             LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrNext32->Flink)) {
            LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);//�Ƿ���ַ��

            //����ת��һ�²��ܴ�ӡ��%Z�Ƕ�STRING32��ӡ�����ġ�
            //���·���е���ʾ�Ĳ��ԣ�Ӧ��WOW64��
            //���˼·������NtQueryVirtualMemory��MmGetFileNameForAddress����RtlPcToFileName�������
            //UNICODE_STRING ImagePathName = {0};
            //ImagePathName.Buffer = (PWCH)LdrEntry32->FullDllName.Buffer;
            //ImagePathName.Length = LdrEntry32->FullDllName.Length;
            //ImagePathName.MaximumLength = LdrEntry32->FullDllName.MaximumLength;            
            //KdPrint(("DllBase:0x%x, Length:0x%08x, FullDllName:%wZ\n",//��Ϊ��32λ�ĵ�ַ���Ͳ���0x%p�ˡ�
            //         LdrEntry32->DllBase, LdrEntry32->SizeOfImage, &ImagePathName));

            //\nt4\private\sdktools\psapi\mapfile.c
            struct
            {
                OBJECT_NAME_INFORMATION ObjectNameInfo;
                WCHAR FileName[1024];//MAX_PATH ����Ϊ1024������ʧ�ܣ�ԭ�򿴣�ObQueryNameString��
            } s = {0};

            NTSTATUS Status = GetMemoryMappedFilenameInformation(NtCurrentProcess(),
                                                                 ULongToPtr(LdrEntry32->DllBase),
                                                                 &s.ObjectNameInfo,
                                                                 sizeof(s));
            if (NT_SUCCESS(Status)) {
                //KdPrint(("FullDllName:%wZ\n", &s.ObjectNameInfo.Name));

                if (CallBack) {
                    Status = CallBack(ULongToPtr(LdrEntry32->DllBase), &s.ObjectNameInfo.Name, Context);
                    if (NT_SUCCESS(Status)) {
                        break;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }
}


void EnumWow64Module(PWOW64_PROCESS pwp, _In_opt_ HandleUserModule CallBack, _In_opt_ PVOID Context)
/*
���ܣ�����һ��WOW64���̵�WOW64ģ�顣

�ο���WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\dbgk\dbgkobj.c��DbgkpPostFakeModuleMessages������

������ʹ�ã�ԭ����2017.02.17�����Գɹ��ģ����죨2022/9/26��ȴ�����ˡ�
*/
{
    PPEB32 Peb32 = (PPEB32)pwp;
    PPEB_LDR_DATA32 Ldr32;
    PLIST_ENTRY32 LdrHead32, LdrNext32;
    PLDR_DATA_TABLE_ENTRY32 LdrEntry32;

    UNREFERENCED_PARAMETER(CallBack);
    UNREFERENCED_PARAMETER(Context);

    //��������ԭ����2017.02.17�����Գɹ��ģ����죨2022/9/26��ȴ�����ˡ�
    __try {
        Ldr32 = (PPEB_LDR_DATA32)UlongToPtr(Peb32->Ldr);
        LdrHead32 = &Ldr32->InLoadOrderModuleList;

        for (LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrHead32->Flink); 
             LdrNext32 != LdrHead32; 
             LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrNext32->Flink)) {           

            LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

            //����ת��һ�²��ܴ�ӡ��%Z�Ƕ�STRING32��ӡ�����ġ�
            //���·���е���ʾ�Ĳ��ԣ�Ӧ��WOW64������NtQueryVirtualMemory��MmGetFileNameForAddress�������
            UNICODE_STRING ImagePathName = {0};
            ImagePathName.Buffer = (PWCH)LdrEntry32->FullDllName.Buffer;
            ImagePathName.Length = LdrEntry32->FullDllName.Length;
            ImagePathName.MaximumLength = LdrEntry32->FullDllName.MaximumLength;

            //��Ϊ��32λ�ĵ�ַ���Ͳ���0x%p�ˡ�
            KdPrint(("DllBase:0x%x, Length:0x%08x, FullDllName:%wZ\n", LdrEntry32->DllBase, LdrEntry32->SizeOfImage, &ImagePathName));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    //��������
    //__try {
    //    PPEB32 peb32 = (PPEB32)pwp;
    //    if (!peb32 || !peb32->Ldr) {
    //        return;
    //    }
    //    for (PLIST_ENTRY32 Entry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)peb32->Ldr)->InLoadOrderModuleList.Flink;
    //         Entry != &((PPEB_LDR_DATA32)peb32->Ldr)->InLoadOrderModuleList;
    //         Entry = (PLIST_ENTRY32)Entry->Flink) {
    //        PLDR_DATA_TABLE_ENTRY32 DataTableEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);            
    //        struct{//\nt4\private\sdktools\psapi\mapfile.c
    //            OBJECT_NAME_INFORMATION ObjectNameInfo;
    //            WCHAR FileName[1024];//MAX_PATH ����Ϊ1024������ʧ�ܣ�ԭ�򿴣�ObQueryNameString��
    //        } s = {0};
    //        NTSTATUS Status = GetMemoryMappedFilenameInformation(NtCurrentProcess(),
    //                                                             ULongToPtr(DataTableEntry->DllBase),
    //                                                             &s.ObjectNameInfo,
    //                                                             sizeof(s));
    //        if (NT_SUCCESS(Status)) {
    //            //KdPrint(("FullDllName:%wZ\n", &s.ObjectNameInfo.Name));
    //            if (CallBack) {
    //                Status = CallBack(ULongToPtr(DataTableEntry->DllBase), &s.ObjectNameInfo.Name, Context);
    //                if (NT_SUCCESS(Status)) {
    //                    break;
    //                }
    //            }
    //        }
    //    }
    //} __except (EXCEPTION_EXECUTE_HANDLER) {
    //    Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    //}

    //����һ��
    //PPEB32 Peb32 = (PPEB32)pwp;
    //PPEB_LDR_DATA32 Ldr32;
    //PLIST_ENTRY32 LdrHead32, LdrNext32;
    //PLDR_DATA_TABLE_ENTRY32 LdrEntry32;

    //__try {
    //    Ldr32 = (PPEB_LDR_DATA32)UlongToPtr(Peb32->Ldr);
    //    LdrHead32 = &Ldr32->InLoadOrderModuleList;
    //    for (LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrHead32->Flink);
    //         LdrNext32 != LdrHead32;
    //         LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrNext32->Flink)) {
    //        LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);//�Ƿ���ַ��

    //        //����ת��һ�²��ܴ�ӡ��%Z�Ƕ�STRING32��ӡ�����ġ�
    //        //���·���е���ʾ�Ĳ��ԣ�Ӧ��WOW64��
    //        //���˼·������NtQueryVirtualMemory��MmGetFileNameForAddress����RtlPcToFileName�������
    //        //UNICODE_STRING ImagePathName = {0};
    //        //ImagePathName.Buffer = (PWCH)LdrEntry32->FullDllName.Buffer;
    //        //ImagePathName.Length = LdrEntry32->FullDllName.Length;
    //        //ImagePathName.MaximumLength = LdrEntry32->FullDllName.MaximumLength;            
    //        //KdPrint(("DllBase:0x%x, Length:0x%08x, FullDllName:%wZ\n",//��Ϊ��32λ�ĵ�ַ���Ͳ���0x%p�ˡ�
    //        //         LdrEntry32->DllBase, LdrEntry32->SizeOfImage, &ImagePathName));

    //        //\nt4\private\sdktools\psapi\mapfile.c
    //        struct
    //        {
    //            OBJECT_NAME_INFORMATION ObjectNameInfo;
    //            WCHAR FileName[1024];//MAX_PATH ����Ϊ1024������ʧ�ܣ�ԭ�򿴣�ObQueryNameString��
    //        } s = {0};

    //        NTSTATUS Status = GetMemoryMappedFilenameInformation(NtCurrentProcess(),
    //                                                             ULongToPtr(LdrEntry32->DllBase),
    //                                                             &s.ObjectNameInfo,
    //                                                             sizeof(s));
    //        if (NT_SUCCESS(Status)) {
    //            //KdPrint(("FullDllName:%wZ\n", &s.ObjectNameInfo.Name));

    //            if (CallBack) {
    //                Status = CallBack(ULongToPtr(LdrEntry32->DllBase), &s.ObjectNameInfo.Name, Context);
    //                if (NT_SUCCESS(Status)) {
    //                    break;
    //                }
    //            }
    //        }
    //    }
    //} __except (EXCEPTION_EXECUTE_HANDLER) {
    //    Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    //}
}


#endif


VOID EnumUserModule(_In_ HANDLE Pid, _In_opt_ HandleUserModule CallBack, _In_opt_ PVOID Context)
/*
���ܣ��оٽ��̵�DLL������32��64��WOW64��

ע�⣺
1.������취ȡImagePathName��IDLE��system������Ӧ�û�ȡ������
2.�˺������ڽ��̻ص��л�ȡ�������ݣ��̻߳ص��ľͲ�˵�ˡ�
3.��Ӷ����ƽ��̻ص������Ƶ���������������û�����顣

���ڴˣ�������������չ����
1.����Ӧ�ò��ģ�飨����32��64��WOW64����
2.ж��Ӧ�ò��ģ�飨����32��64��WOW64����
3.��ȡӦ�ò��API�ĵ�ַ������32��64��WOW64����

made by correy
made at 2017.02.17
homepage:http://correy.webs.com
*/
{
    PEPROCESS    Process;
    NTSTATUS     Status = STATUS_SUCCESS;
    KAPC_STATE   ApcState;
    PPEB peb = 0;
    PLIST_ENTRY le1, le2;
    PLDR_DATA_TABLE_ENTRY pldte;

    if (0 == Pid) {
        return;//IDLE
    }

    if (PsGetProcessId(PsInitialSystemProcess) == Pid) //PsIsSystemThread
    {
        return;//system
    }

    Status = PsLookupProcessByProcessId(Pid, &Process);
    if (!NT_SUCCESS(Status)) {
        return;//��Ч���̡�
    }

    KeStackAttachProcess(Process, &ApcState);

    peb = PsGetProcessPeb(Process);//ע�⣺IDLE��system������Ӧ�û�ȡ������
    if (peb) {
        __try {
            if (peb->Ldr) {
                le1 = peb->Ldr->InMemoryOrderModuleList.Flink;
                le2 = le1;
                do {
                    pldte = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(le1, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    if (pldte->FullDllName.Length) //���˵����һ��������ġ�
                    {
                        KdPrint(("FullDllName:%wZ \n", &pldte->FullDllName));

                        if (CallBack) {
                            Status = CallBack(pldte->DllBase, &pldte->FullDllName, Context);
                            if (NT_SUCCESS(Status)) {
                                break;
                            }
                        }
                    }

                    le1 = le1->Flink;
                } while (le1 != le2);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
        }

    #if defined(_WIN64)
        //�����WOW64������Ҫִ������Ĵ��룬����Ҫ����ж�WOW64�Ĵ��롣
        //ZwQueryInformationProcess +��ProcessWow64Information
        PWOW64_PROCESS pwp = (PWOW64_PROCESS)PsGetProcessWow64Process(Process);
        if (NULL != pwp) {
            EnumWow64Module(pwp, CallBack, Context);
        }
    #endif
    } else {//win10���в��ٽ�����û���û��ռ�ģ�Ҳû�������С�
        KdPrint(("����:%dû��PEB(�û���ռ�).\n", HandleToLong(Pid)));
    }

    KeUnstackDetachProcess(&ApcState);

    ObDereferenceObject(Process);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#if (NTDDI_VERSION >= NTDDI_VISTA)
PVOID GetNtBase()
/*
���ܣ���ȡNT�ں˵Ļ���ַ��

��ʵ��һ�����򵥵İ취��ֻ��֪��NT���һ����ַ��Ȼ�����һ���������ɻ�ã����API����RtlPcToFileHeader��

���л�����˵��NTDDI_VISTA����ʵ2003�����ˣ������е�WDK�ﲻ������Ӧ��lib��Aux_klib.lib����
*/
{
    NTSTATUS Status = 0;
    ULONG  modulesSize = 0;
    PAUX_MODULE_EXTENDED_INFO modules;
    ULONG  numberOfModules;
    ULONG i;
    PVOID ImageBase = 0;

    Status = AuxKlibInitialize();
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return ImageBase;
    }

    // Get the required array size.
    Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(Status) || modulesSize == 0) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return ImageBase;
    }

    // Calculate the number of modules.
    numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

    // Allocate memory to receive data.
    modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(PagedPool, modulesSize, TAG);
    if (modules == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return ImageBase;
    }
    RtlZeroMemory(modules, modulesSize);

    // Obtain the module information.
    Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(modules, TAG);
        return ImageBase;
    }

    for (i = 0; i < numberOfModules; i++) {
        //UCHAR * FileName = modules[i].FullPathName + modules[i].FileNameOffset;

        if (i == 0) {
            ImageBase = modules[i].BasicInfo.ImageBase;
            break;
        }
    }

    ExFreePoolWithTag(modules, TAG);

    return ImageBase;
}
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
PVOID GetImageBase(__in PCSTR Name)
/*
���ܣ���ȡһ���ں�ģ��Ļ���ַ�����������û��NTDLL����

���л�����˵��NTDDI_VISTA����ʵ2003�����ˣ������е�WDK�ﲻ������Ӧ��lib��Aux_klib.lib����
*/
{
    NTSTATUS Status = 0;
    ULONG  modulesSize = 0;
    PAUX_MODULE_EXTENDED_INFO modules;
    ULONG  numberOfModules;
    ULONG i;
    PVOID ImageBase = 0;

    Status = AuxKlibInitialize();
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return ImageBase;
    }

    // Get the required array size.
    Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(Status) || modulesSize == 0) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return ImageBase;
    }

    // Calculate the number of modules.
    numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

    // Allocate memory to receive data.
    modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(PagedPool, modulesSize, TAG);
    if (modules == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return ImageBase;
    }
    RtlZeroMemory(modules, modulesSize);

    // Obtain the module information.
    Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(modules, TAG);
        return ImageBase;
    }

    for (i = 0; i < numberOfModules; i++) {
    #pragma prefast(push)
    #pragma prefast(disable: 6385, "�ӡ�modules���ж�ȡ��������Ч: �ɶ���СΪ��_Old_8`modulesSize�����ֽڣ������ܶ�ȡ�ˡ�536�����ֽڡ�")
        UCHAR * FileName = modules[i].FullPathName + modules[i].FileNameOffset;
    #pragma prefast(pop)        

        if (_stricmp((const char *)FileName, Name) == 0) {
            ImageBase = modules[i].BasicInfo.ImageBase;
            break;
        }
    }

    ExFreePoolWithTag(modules, TAG);

    return ImageBase;
}
#endif


#if (NTDDI_VERSION >= NTDDI_VISTA)
NTSTATUS EnumKernelModule(_In_ HandleKernelModule CallBack, _In_opt_ PVOID Context)
/*
���ܣ�ͨ�õĴ���ÿ���ں�ģ��ĺ�����

��ʵ��һ�����򵥵İ취��ֻ��֪��NT���һ����ַ��Ȼ�����һ���������ɻ�ã����API����RtlPcToFileHeader��

���л�����˵��NTDDI_VISTA����ʵ2003�����ˣ������е�WDK�ﲻ������Ӧ��lib��Aux_klib.lib����

��ʵֻҪ����Aux_klib.lib����XP��2003��Ҳ�����ã���Ϊ����Ǿ�̬���ӵġ�
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PAUX_MODULE_EXTENDED_INFO modules;

    Status = AuxKlibInitialize();
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return Status;
    }

    // Get the required array size.
    ULONG  modulesSize = 0;
    Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!NT_SUCCESS(Status) || modulesSize == 0) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return Status;
    }

    ULONG numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);// Calculate the number of modules.

    // Allocate memory to receive data.
    modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(PagedPool, modulesSize, TAG);
    if (modules == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return Status;
    }
    RtlZeroMemory(modules, modulesSize);

    // Obtain the module information.
    Status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(modules, TAG);
        return Status;
    }

    if (CallBack) {
        CallBack(numberOfModules, modules, Context);
    }

    ExFreePoolWithTag(modules, TAG);

    return Status;
}
#endif


PVOID GetNtdllImageBase(PEPROCESS Process)
/*
���ܣ���ȡһ�����̵�ntdll.dll����ַ��

ע�⣺�����64λ����ϵͳ�ϣ���ȡ���Ǳ����ģ���WOW64�ġ�

��֧��IDLE��SYStem���̡�
*/
{
    //////////////////////////////////////////////////////////////////////////////////////////////

    UNICODE_STRING g_SystemRoot = RTL_CONSTANT_STRING(L"\\SystemRoot");
    wchar_t NtSystemRoot[MAX_PATH] = {0};
    UNICODE_STRING g_NtSystemRoot = {0};
    wchar_t DosSystemRoot[MAX_PATH] = {0};
    UNICODE_STRING g_DosSystemRoot = {0};

    UNICODE_STRING g_NTDLL = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
    wchar_t NtNTDLL[MAX_PATH] = {0};
    UNICODE_STRING g_NtNTDLL = {0};
    wchar_t DosNTDLL[MAX_PATH] = {0};
    UNICODE_STRING g_DosNTDLL = {0};

    UNICODE_STRING g_Smss = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\smss.exe");
    wchar_t NtSmss[MAX_PATH] = {0};
    UNICODE_STRING g_NtSmss = {0};
    wchar_t DosSmss[MAX_PATH] = {0};
    UNICODE_STRING g_DosSmss = {0};

    UNICODE_STRING g_Csrss = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\csrss.exe");
    wchar_t NtCsrss[MAX_PATH] = {0};
    UNICODE_STRING g_NtCsrss = {0};
    wchar_t DosCsrss[MAX_PATH] = {0};
    UNICODE_STRING g_DosCsrss = {0};

    //////////////////////////////////////////////////////////////////////////////////////////////

    RtlInitUnicodeString(&g_NtSystemRoot, NtSystemRoot);
    g_NtSystemRoot.MaximumLength = sizeof(NtSystemRoot);
    RtlInitUnicodeString(&g_DosSystemRoot, DosSystemRoot);
    g_DosSystemRoot.MaximumLength = sizeof(DosSystemRoot);

    RtlInitUnicodeString(&g_NtNTDLL, NtNTDLL);
    g_NtNTDLL.MaximumLength = sizeof(NtNTDLL);
    RtlInitUnicodeString(&g_DosNTDLL, DosNTDLL);
    g_DosNTDLL.MaximumLength = sizeof(DosNTDLL);

    RtlInitUnicodeString(&g_NtSmss, NtSmss);
    g_NtSmss.MaximumLength = sizeof(NtSmss);
    RtlInitUnicodeString(&g_DosSmss, DosSmss);
    g_DosSmss.MaximumLength = sizeof(DosSmss);

    RtlInitUnicodeString(&g_NtCsrss, NtCsrss);
    g_NtCsrss.MaximumLength = sizeof(NtCsrss);
    RtlInitUnicodeString(&g_DosCsrss, DosCsrss);
    g_DosCsrss.MaximumLength = sizeof(DosCsrss);

    GetSystemRootPathName(&g_SystemRoot, &g_NtSystemRoot, &g_DosSystemRoot);
    GetSystemRootPathName(&g_NTDLL, &g_NtNTDLL, &g_DosNTDLL);
    GetSystemRootPathName(&g_Smss, &g_NtSmss, &g_DosSmss);
    GetSystemRootPathName(&g_Csrss, &g_NtCsrss, &g_DosCsrss);

    //////////////////////////////////////////////////////////////////////////////////////////////

    PPEB         ppeb;
    PLDR_DATA_TABLE_ENTRY pldte;
    PLIST_ENTRY le1, le2;
    PVOID ImageBase = 0;

    ppeb = PsGetProcessPeb(Process);//ע�⣺IDLE��system������Ӧ�û�ȡ������
#if defined(_AMD64_) || defined(_IA64_) //defined(_WIN64_) 
    le1 = ppeb->Ldr->InMemoryOrderModuleList.Flink;
#else
    le1 = ppeb->Ldr->InMemoryOrderModuleList.Flink;
#endif 
    le2 = le1;

    do {
        pldte = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(le1, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pldte->FullDllName.Length && pldte->FullDllName.Buffer) //���˵����һ��������ġ�
        {
            //KdPrint(("FullDllName:%wZ \n", &pldte->FullDllName));  

            if (RtlCompareUnicodeString(&pldte->FullDllName, &g_NtNTDLL, TRUE) == 0 ||
                RtlCompareUnicodeString(&pldte->FullDllName, &g_DosNTDLL, TRUE) == 0 ||
                RtlCompareUnicodeString(&pldte->FullDllName, &g_NTDLL, TRUE) == 0
                //�ں���û�����Ի���������ͷ��·�����磺%systemroot%.
                ) {
                ImageBase = pldte->DllBase;
                break;
            }
        }

        le1 = le1->Flink;
    } while (le1 != le2);

    return ImageBase;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS NTAPI HandleOneSection(_In_ PVOID ViewBase, _In_ SIZE_T ViewSize, _In_opt_ PVOID Context)
/*
˵�����ں�ӳ��Ļص���������������

�˻ص�ֻ�ᱻ����һ�Ρ�
*/
{
    UNREFERENCED_PARAMETER(ViewBase);
    UNREFERENCED_PARAMETER(ViewSize);
    UNREFERENCED_PARAMETER(Context);

    return STATUS_SUCCESS;
}


BOOLEAN MapViewOfSection(_In_ PUNICODE_STRING ImageFileName, _In_opt_ HandleSection CallBack, _In_opt_ PVOID Context)
/*
���ܣ�ͨ�õ��ں�ӳ�䴦������

�ں��е��ļ�ӳ�䡣
Ӧ�û���ͦ�㷺�ģ��磺����Ӧ�ò��DLL���磺kernel32.dll��ntdll.dll�ȡ�
ע�⣺�Լ���ӳ�仹�ǱȽϸɾ��ģ�û�и���HOOK����inline��IAT��EAT�ȡ�

��ӳ��ӳ�䵽��PsInitialSystemProcess���̡�

made by correy
made at 2017/05/29
http://correy.webs.com

�˺����ο���WRK��IopIsNotNativeDriverImage��

�÷�ʾ����MapViewOfSection(&PsNtDllPathName);
*/
{
    HANDLE ImageFileHandle = nullptr;
    IO_STATUS_BLOCK IoStatus{};
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Section = nullptr;
    PVOID ViewBase = nullptr;
    SIZE_T ViewSize = 0;
    KAPC_STATE ApcState{};
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN RetValue = FALSE;
    HANDLE  Handle = nullptr;

    __try {
        // Attempt to open the driver image itself.
        // If this fails, then the driver image cannot be located, so nothing else matters.
        InitializeObjectAttributes(&ObjectAttributes,
                                   ImageFileName,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL,
                                   NULL);
        Status = ZwOpenFile(&ImageFileHandle,
                            FILE_EXECUTE,
                            &ObjectAttributes,
                            &IoStatus,
                            FILE_SHARE_READ | FILE_SHARE_DELETE,
                            0);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            __leave;
        }

        InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        Status = ZwCreateSection(&Section,
                                 SECTION_MAP_EXECUTE,//SECTION_MAP_READ
                                 &ObjectAttributes,
                                 NULL,
                                 PAGE_EXECUTE,//PAGE_READONLY
                                 SEC_COMMIT,
                                 ImageFileHandle);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = ObOpenObjectByPointer(PsInitialSystemProcess,
                                       OBJ_KERNEL_HANDLE,
                                       NULL,
                                       GENERIC_READ,
                                       *PsProcessType,
                                       KernelMode,
                                       &Handle);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = ZwMapViewOfSection(Section, Handle, &ViewBase, 0L, 0L, NULL, &ViewSize, ViewShare, 0L, PAGE_EXECUTE);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            __leave;;
        }

        RetValue = TRUE;

        // Since callees are not always in the context of the system process, 
        // attach here when necessary to guarantee the driver load occurs in a known safe address space to prevent security holes.
        KeStackAttachProcess(PsInitialSystemProcess, &ApcState);

        __try {
            if (CallBack) {
                CallBack(ViewBase, ViewSize, Context);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
            RetValue = FALSE;
        }

        KeUnstackDetachProcess(&ApcState);
    } __finally {
        if (Handle && ViewBase) {
            ZwUnmapViewOfSection(Handle, ViewBase);
        }

        if (Section) {
            ZwClose(Section);
        }

        if (ImageFileHandle) {
            ZwClose(ImageFileHandle);
        }

        if (Handle) {
            ZwClose(Handle);
        }
    }

    return RetValue;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS ZwGetSystemModuleInformation()
/*
�ο���WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\perf\hooks.c��PerfInfoSysModuleRunDown������
*/
{
    NTSTATUS Status;
    PRTL_PROCESS_MODULES Modules;
    PVOID Buffer;
    ULONG BufferSize = 4096;
    ULONG ReturnLength;

retry:
    Buffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, TAG);
    if (!Buffer) {
        return STATUS_NO_MEMORY;
    }
    Status = ZwQuerySystemInformation(SystemModuleInformation, Buffer, BufferSize, &ReturnLength);
    if (Status == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePool(Buffer);
        BufferSize = ReturnLength;
        goto retry;
    }

    Modules = (PRTL_PROCESS_MODULES)Buffer;

    if (NT_SUCCESS(Status)) {
        PRTL_PROCESS_MODULE_INFORMATION ModuleInfo;
        ULONG i = 0;

        for (ModuleInfo = &Modules->Modules[0]; i < Modules->NumberOfModules; i++, ModuleInfo++) {
            ANSI_STRING    AstrModuleName;
            RtlInitAnsiString(&AstrModuleName, (PCSZ)ModuleInfo->FullPathName);

            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "FullPathName:%Z", &AstrModuleName);
        }
    }

    ExFreePoolWithTag(Buffer, TAG);
    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID ImageLoadedThreadEx(_In_ PVOID Parameter)
{
    PLOAD_IMAGE_CONTEXT ctx = (PLOAD_IMAGE_CONTEXT)Parameter;

    PAGED_CODE();

    ctx->info.Status = GetFileObjectDosName(ctx->info.ImageInfoEx->FileObject, &ctx->info.ImageLoaded);

    KeSetEvent(ctx->Event, IO_NO_INCREMENT, FALSE);
}


VOID ImageLoadedThread(_In_ PVOID Parameter)
{
    PLOAD_IMAGE_CONTEXT ctx = (PLOAD_IMAGE_CONTEXT)Parameter;
    HANDLE File;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus;
    PFILE_OBJECT FileObject;
    UNICODE_STRING FullName = {0};

    PAGED_CODE();

    InitializeObjectAttributes(&ObjectAttributes, ctx->info.FullImageName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ctx->info.Status = ZwOpenFile(&File, SYNCHRONIZE | FILE_EXECUTE, &ObjectAttributes, &IoStatus, FILE_SHARE_READ, 0);
    if (NT_SUCCESS(ctx->info.Status)) {
        ctx->info.Status = ObReferenceObjectByHandle(File, FILE_READ_ACCESS, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, 0);
        if (NT_SUCCESS(ctx->info.Status)) {
            ctx->info.Status = GetFileObjectDosName(FileObject, &FullName);
            ASSERT(NT_SUCCESS(ctx->info.Status));

            ctx->info.ImageLoaded.MaximumLength = FullName.MaximumLength + sizeof(wchar_t);
            ctx->info.ImageLoaded.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, ctx->info.ImageLoaded.MaximumLength, TAG);//�ɵ������ͷš�
            ASSERT(ctx->info.ImageLoaded.Buffer);
            RtlZeroMemory(ctx->info.ImageLoaded.Buffer, ctx->info.ImageLoaded.MaximumLength);

            //KdPrint(("DOS name:%wZ.\r\n", &FullName));
            RtlCopyUnicodeString(&ctx->info.ImageLoaded, &FullName);

            if (FullName.Buffer) {
                ExFreePoolWithTag(FullName.Buffer, TAG);
            }
            ObDereferenceObject(FileObject);
        } else {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:0x%#x, FileName:%wZ", ctx->info.Status, ctx->info.FullImageName);
        }

        ZwClose(File);
    } else {
        FileObject = CONTAINING_RECORD(ctx->info.FullImageName, FILE_OBJECT, FileName);
        ASSERT(FileObject);

        ctx->info.Status = GetFileObjectDosName(FileObject, &FullName);
        if (NT_SUCCESS(ctx->info.Status)) {
            ctx->info.ImageLoaded.MaximumLength = FullName.MaximumLength + sizeof(wchar_t);
            ctx->info.ImageLoaded.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, ctx->info.ImageLoaded.MaximumLength, TAG);//�ɵ������ͷš�
            ASSERT(ctx->info.ImageLoaded.Buffer);
            RtlZeroMemory(ctx->info.ImageLoaded.Buffer, ctx->info.ImageLoaded.MaximumLength);

            RtlCopyUnicodeString(&ctx->info.ImageLoaded, &FullName);
        } else {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:0x%#x, FileName:%wZ", ctx->info.Status, ctx->info.FullImageName);
        }

        if (FullName.Buffer) {
            ExFreePoolWithTag(FullName.Buffer, TAG);
        }
    }

    KeSetEvent(ctx->Event, IO_NO_INCREMENT, FALSE);
}


VOID NTAPI RtlGetLoadImageFullName(_Inout_ PUNICODE_STRING LoadImageFullName,
                                   __in_opt PUNICODE_STRING  FullImageName,
                                   __in HANDLE  ProcessId,
                                   __in PIMAGE_INFO  ImageInfo
)
/*
���ܣ���LoadImageNotifyRoutine�л�ȡLoadImage��ȫ·����

������XP��VISTA��windows 7/8/8.1/10���Լ�Windows server 2003/2008/2012/2016/2019�ȡ�

��Ҫ˵����
1.XP��FullImageName��FILE_OBJECT��FileName���������Ҳ��һ����������·����
2.windows 7�´�ʱ����������ֱ�ӻ�ȡ����Ҫһ��WorkItem���������������
3.windows 8.1֮��ܼ��ˡ�
4.FullImageName��·���������ģ���Եģ������������ĵȺ��п��ܡ�
5.

ע�⣺
1.�˺���ֻ������LoadImageNotifyRoutine�С�
2.�������سɹ���FullImageName���ڴ��ɵ������ͷš�
3.

�÷�ʾ����
UNICODE_STRING LoadImageFullName = {0};
RtlGetLoadImageFullName(&LoadImageFullName, FullImageName, ProcessId, ImageInfo);
...
FreeUnicodeString(&LoadImageFullName);
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    KEVENT event;
    PLOAD_IMAGE_CONTEXT ctx = NULL;

    ctx = (PLOAD_IMAGE_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(LOAD_IMAGE_CONTEXT), TAG);
    ASSERT(ctx);
    RtlZeroMemory(ctx, sizeof(LOAD_IMAGE_CONTEXT));
    ctx->Event = &event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    if (ImageInfo->ExtendedInfoPresent) {
        PIMAGE_INFO_EX ImageInfoEx = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);

        ASSERT(ImageInfoEx);

        ctx->info.ImageInfoEx = ImageInfoEx;
        ExInitializeWorkItem(&ctx->hdr, ImageLoadedThreadEx, ctx);
    } else {
        /*
        ��ʱ��FileFullName���м��ֲ�ͬ�ı�����ʽ����Ӧ����VISTA֮ǰ���֡�
        */

        ctx->info.ImageInfo = ImageInfo;
        ctx->info.ProcessId = ProcessId;
        ctx->info.FullImageName = FullImageName;

        ExInitializeWorkItem(&ctx->hdr, ImageLoadedThread, ctx);
    }

    ExQueueWorkItem(&ctx->hdr, DelayedWorkQueue);
    Status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
    if (NT_SUCCESS(Status) && NT_SUCCESS(ctx->info.Status)) {
        if (ctx->info.ImageLoaded.Buffer != NULL) {
            LoadImageFullName->MaximumLength = ctx->info.ImageLoaded.MaximumLength + sizeof(wchar_t);
            LoadImageFullName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, LoadImageFullName->MaximumLength, TAG);//�ɵ������ͷš�
            ASSERT(LoadImageFullName->Buffer);
            RtlZeroMemory(LoadImageFullName->Buffer, LoadImageFullName->MaximumLength);

            RtlCopyUnicodeString(LoadImageFullName, &ctx->info.ImageLoaded);

            ExFreePoolWithTag(ctx->info.ImageLoaded.Buffer, TAG);
        } else {
            KdPrint(("FILE:%s, LINE:%d.\r\n", __FILE__, __LINE__));
        }
    } else {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:0x%#x", Status);
    }

    ExFreePoolWithTag(ctx, TAG);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID NTAPI HideDriver(_In_ PDRIVER_OBJECT DriverObject)
/*

û�뵽�������д��2012�꣬�����ɻ�����Ըı�ġ�
*/
{
    KIRQL Irql = KeRaiseIrqlToDpcLevel(); 

    PKLDR_DATA_TABLE_ENTRY DriverSection = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (NULL != DriverSection) {  //������������ժ��������������
        //RemoveHeadList(&DriverSection->InLoadOrderLinks);

        *((SIZE_T *)DriverSection->InLoadOrderLinks.Blink) = (SIZE_T)DriverSection->InLoadOrderLinks.Flink;
        DriverSection->InLoadOrderLinks.Flink->Blink = DriverSection->InLoadOrderLinks.Blink;

        //�������ֹ������
        DriverSection->InLoadOrderLinks.Flink = (PLIST_ENTRY)&(DriverSection->InLoadOrderLinks.Flink);
        DriverSection->InLoadOrderLinks.Blink = (PLIST_ENTRY)&(DriverSection->InLoadOrderLinks.Flink);

        ////����������ȫ·�����������������¼��ؿ����е����⡣
        //DriverSection->FullDllName.Length = 0;
        //DriverSection->FullDllName.MaximumLength = 0;
        //DriverSection->FullDllName.Buffer = 0;

        ////�����������ļ�����
        //DriverSection->BaseDllName.Length = 0;
        //DriverSection->BaseDllName.MaximumLength = 0;
        //DriverSection->BaseDllName.Buffer = 0;

        //��������������ػ�����Ӵ��
    }

    KeLowerIrql(Irql);
}
