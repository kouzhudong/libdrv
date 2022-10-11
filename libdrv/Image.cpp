#include "pch.h"
#include "Image.h"
#include "Process.h"
#include "File.h"
#include "object.h"
#include "ssdt.h"


#pragma warning(disable:4366) //一元“&”运算符的结果可能是未对齐的


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS GetMemoryMappedFilenameInformation(_In_ HANDLE KernelProcessHandle, 
                                            _In_opt_ PVOID DllBase,
                                            _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                                            _In_ SIZE_T MemoryInformationLength
)
/*
说明：此函数主要是用户获取应用层的相应地址的映射文件的全路径。

因为WOW64_PEB获取的ImagePathName不对，因为含有system32,这是绝对不对的。
这里应该肯定：这些结构是正确的。
所以只有认为ImagePathName不对了。

但是此时已经获取了：DllBase，SizeOfImage，BaseDllName，而且这些是正确的。
注意：NLS等非常规的DLL是不包含的。

所以这里有根据这些获取ImagePathName的问题和功能。

MmGetFileNameForAddress函数未导出，不建议使用。
AuxKlibQueryModuleInformation只能获取内核的，是RtlQueryModuleInformation的封装，这又是别的封装。
ZwQueryVirtualMemory MemoryMappedFilenameInformation MEMORY_MAPPED_FILE_NAME_INFORMATION

ZwQueryVirtualMemory，虽然Windows近期才公开，但是早期是不导出的，所以要动态获取这个函数的地址。
尽管\Windows Kits\10\Include\10.0.19041.0\km\ntifs.h加了(NTDDI_VERSION >= NTDDI_WIN2K)。

ZwQueryVirtualMemory使用有几个注意事项：
1.此函数不能在回调中直接运行，在WorkItemThread中运行成功，否者返回STATUS_ACCESS_VIOLATION。
2.此时的句柄必须是内核态的进程句柄。
3.此函数不需要AttachProcess，因为它带有进程的句柄。
4.NtQueryVirtualMemory会有进去出不来的情况，即卡在那里了，这个函数内部用两个锁。
  只有一个工作线程，也会出现，所以用自己的工作线程排队也解决不了。
5.如果第一个参数是NtCurrentProcess()，建议用KeStackAttachProcess。

参考函数：
MmGetFileNameForAddress
0: kd> x nt!RtlPcTo* 这几个函数应该仅仅支持内核模块
fffff804`65544fb0 nt!RtlPcToFileHeader (RtlPcToFileHeader)
fffff804`65b169e0 nt!RtlPcToFilePath (RtlPcToFilePath)
fffff804`655c95d0 nt!RtlPcToFileName (RtlPcToFileName)

调用此函数前需先调用SetZwQueryVirtualMemoryAddress函数。
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
功能：遍历一个WOW64进程的WOW64模块。

参考：WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\dbgk\dbgkobj.c的DbgkpPostFakeModuleMessages函数。
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
            LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);//非法地址。

            //必须转换一下才能打印。%Z是对STRING32打印不出的。
            //这个路径有的显示的不对，应是WOW64。
            //解决思路：可用NtQueryVirtualMemory或MmGetFileNameForAddress或者RtlPcToFileName来解决。
            //UNICODE_STRING ImagePathName = {0};
            //ImagePathName.Buffer = (PWCH)LdrEntry32->FullDllName.Buffer;
            //ImagePathName.Length = LdrEntry32->FullDllName.Length;
            //ImagePathName.MaximumLength = LdrEntry32->FullDllName.MaximumLength;            
            //KdPrint(("DllBase:0x%x, Length:0x%08x, FullDllName:%wZ\n",//因为是32位的地址，就不用0x%p了。
            //         LdrEntry32->DllBase, LdrEntry32->SizeOfImage, &ImagePathName));

            //\nt4\private\sdktools\psapi\mapfile.c
            struct
            {
                OBJECT_NAME_INFORMATION ObjectNameInfo;
                WCHAR FileName[1024];//MAX_PATH 必须为1024，否则失败，原因看：ObQueryNameString。
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
功能：遍历一个WOW64进程的WOW64模块。

参考：WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\dbgk\dbgkobj.c的DbgkpPostFakeModuleMessages函数。

不建议使用：原来（2017.02.17）测试成功的，今天（2022/9/26）却不行了。
*/
{
    PPEB32 Peb32 = (PPEB32)pwp;
    PPEB_LDR_DATA32 Ldr32;
    PLIST_ENTRY32 LdrHead32, LdrNext32;
    PLDR_DATA_TABLE_ENTRY32 LdrEntry32;

    UNREFERENCED_PARAMETER(CallBack);
    UNREFERENCED_PARAMETER(Context);

    //方法三：原来（2017.02.17）测试成功的，今天（2022/9/26）却不行了。
    __try {
        Ldr32 = (PPEB_LDR_DATA32)UlongToPtr(Peb32->Ldr);
        LdrHead32 = &Ldr32->InLoadOrderModuleList;

        for (LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrHead32->Flink); 
             LdrNext32 != LdrHead32; 
             LdrNext32 = (PLIST_ENTRY32)UlongToPtr(LdrNext32->Flink)) {           

            LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

            //必须转换一下才能打印。%Z是对STRING32打印不出的。
            //这个路径有的显示的不对，应是WOW64，可用NtQueryVirtualMemory或MmGetFileNameForAddress来解决。
            UNICODE_STRING ImagePathName = {0};
            ImagePathName.Buffer = (PWCH)LdrEntry32->FullDllName.Buffer;
            ImagePathName.Length = LdrEntry32->FullDllName.Length;
            ImagePathName.MaximumLength = LdrEntry32->FullDllName.MaximumLength;

            //因为是32位的地址，就不用0x%p了。
            KdPrint(("DllBase:0x%x, Length:0x%08x, FullDllName:%wZ\n", LdrEntry32->DllBase, LdrEntry32->SizeOfImage, &ImagePathName));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    //方法二。
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
    //            WCHAR FileName[1024];//MAX_PATH 必须为1024，否则失败，原因看：ObQueryNameString。
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

    //方法一。
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
    //        LdrEntry32 = CONTAINING_RECORD(LdrNext32, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);//非法地址。

    //        //必须转换一下才能打印。%Z是对STRING32打印不出的。
    //        //这个路径有的显示的不对，应是WOW64。
    //        //解决思路：可用NtQueryVirtualMemory或MmGetFileNameForAddress或者RtlPcToFileName来解决。
    //        //UNICODE_STRING ImagePathName = {0};
    //        //ImagePathName.Buffer = (PWCH)LdrEntry32->FullDllName.Buffer;
    //        //ImagePathName.Length = LdrEntry32->FullDllName.Length;
    //        //ImagePathName.MaximumLength = LdrEntry32->FullDllName.MaximumLength;            
    //        //KdPrint(("DllBase:0x%x, Length:0x%08x, FullDllName:%wZ\n",//因为是32位的地址，就不用0x%p了。
    //        //         LdrEntry32->DllBase, LdrEntry32->SizeOfImage, &ImagePathName));

    //        //\nt4\private\sdktools\psapi\mapfile.c
    //        struct
    //        {
    //            OBJECT_NAME_INFORMATION ObjectNameInfo;
    //            WCHAR FileName[1024];//MAX_PATH 必须为1024，否则失败，原因看：ObQueryNameString。
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
功能：列举进程的DLL，兼容32和64及WOW64。

注意：
1.用这个办法取ImagePathName，IDLE和system这两个应该获取不到。
2.此函数用在进程回调中获取不到内容，线程回调的就不说了。
3.添加对类似进程回调等类似的情况，正常情况下没有试验。

基于此，可以做到（扩展）：
1.隐藏应用层的模块（兼容32和64及WOW64）。
2.卸载应用层的模块（兼容32和64及WOW64）。
3.获取应用层的API的地址（兼容32和64及WOW64）。

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
        return;//无效进程。
    }

    KeStackAttachProcess(Process, &ApcState);

    peb = PsGetProcessPeb(Process);//注意：IDLE和system这两个应该获取不到。
    if (peb) {
        __try {
            if (peb->Ldr) {
                le1 = peb->Ldr->InMemoryOrderModuleList.Flink;
                le2 = le1;
                do {
                    pldte = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(le1, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    if (pldte->FullDllName.Length) //过滤掉最后一个，多余的。
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
        //如果是WOW64进程需要执行下面的代码，所以要添加判断WOW64的代码。
        //ZwQueryInformationProcess +　ProcessWow64Information
        PWOW64_PROCESS pwp = (PWOW64_PROCESS)PsGetProcessWow64Process(Process);
        if (NULL != pwp) {
            EnumWow64Module(pwp, CallBack, Context);
        }
    #endif
    } else {//win10上有不少进程是没有用户空间的，也没有命令行。
        KdPrint(("进程:%d没有PEB(用户层空间).\n", HandleToLong(Pid)));
    }

    KeUnstackDetachProcess(&ApcState);

    ObDereferenceObject(Process);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#if (NTDDI_VERSION >= NTDDI_VISTA)
PVOID GetNtBase()
/*
功能：获取NT内核的基地址。

其实有一个更简单的办法，只有知道NT里的一个地址，然后调用一个函数即可获得，这个API便是RtlPcToFileHeader。

运行环境，说是NTDDI_VISTA，其实2003都有了，但是有的WDK里不包含相应的lib（Aux_klib.lib）。
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
功能：获取一个内核模块的基地址（你猜你面有没有NTDLL）。

运行环境，说是NTDDI_VISTA，其实2003都有了，但是有的WDK里不包含相应的lib（Aux_klib.lib）。
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
    #pragma prefast(disable: 6385, "从“modules”中读取的数据无效: 可读大小为“_Old_8`modulesSize”个字节，但可能读取了“536”个字节。")
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
功能：通用的处理每个内核模块的函数。

其实有一个更简单的办法，只有知道NT里的一个地址，然后调用一个函数即可获得，这个API便是RtlPcToFileHeader。

运行环境，说是NTDDI_VISTA，其实2003都有了，但是有的WDK里不包含相应的lib（Aux_klib.lib）。

其实只要包含Aux_klib.lib，在XP和2003上也可以用，因为这个是静态连接的。
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
功能：获取一个进程的ntdll.dll基地址。

注意：这个在64位操作系统上，获取的是本机的，非WOW64的。

不支持IDLE和SYStem进程。
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

    ppeb = PsGetProcessPeb(Process);//注意：IDLE和system这两个应该获取不到。
#if defined(_AMD64_) || defined(_IA64_) //defined(_WIN64_) 
    le1 = ppeb->Ldr->InMemoryOrderModuleList.Flink;
#else
    le1 = ppeb->Ldr->InMemoryOrderModuleList.Flink;
#endif 
    le2 = le1;

    do {
        pldte = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(le1, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pldte->FullDllName.Length && pldte->FullDllName.Buffer) //过滤掉最后一个，多余的。
        {
            //KdPrint(("FullDllName:%wZ \n", &pldte->FullDllName));  

            if (RtlCompareUnicodeString(&pldte->FullDllName, &g_NtNTDLL, TRUE) == 0 ||
                RtlCompareUnicodeString(&pldte->FullDllName, &g_DosNTDLL, TRUE) == 0 ||
                RtlCompareUnicodeString(&pldte->FullDllName, &g_NTDLL, TRUE) == 0
                //内核里没见过以环境变量开头的路径，如：%systemroot%.
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
说明：内核映射的回调处理函数的样例。

此回调只会被调用一次。
*/
{
    UNREFERENCED_PARAMETER(ViewBase);
    UNREFERENCED_PARAMETER(ViewSize);
    UNREFERENCED_PARAMETER(Context);

    return STATUS_SUCCESS;
}


BOOLEAN MapViewOfSection(_In_ PUNICODE_STRING ImageFileName, _In_opt_ HandleSection CallBack, _In_opt_ PVOID Context)
/*
功能：通用的内核映射处理函数。

内核中的文件映射。
应用还是挺广泛的，如：分析应用层的DLL，如：kernel32.dll，ntdll.dll等。
注意：自己的映射还是比较干净的，没有各种HOOK，如inline和IAT，EAT等。

此映射映射到了PsInitialSystemProcess进程。

made by correy
made at 2017/05/29
http://correy.webs.com

此函数参考：WRK的IopIsNotNativeDriverImage。

用法示例：MapViewOfSection(&PsNtDllPathName);
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
参考：WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\perf\hooks.c的PerfInfoSysModuleRunDown函数。
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
            ctx->info.ImageLoaded.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, ctx->info.ImageLoaded.MaximumLength, TAG);//由调用者释放。
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
            ctx->info.ImageLoaded.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, ctx->info.ImageLoaded.MaximumLength, TAG);//由调用者释放。
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
功能：在LoadImageNotifyRoutine中获取LoadImage的全路径。

适用于XP，VISTA，windows 7/8/8.1/10，以及Windows server 2003/2008/2012/2016/2019等。

简要说明：
1.XP下FullImageName是FILE_OBJECT的FileName。所以这个也不一定是完整的路径。
2.windows 7下此时有锁，不可直接获取，需要一个WorkItem解决，否则蓝屏。
3.windows 8.1之后很简单了。
4.FullImageName的路径非完整的，相对的，带环境变量的等后有可能。
5.

注意：
1.此函数只适用于LoadImageNotifyRoutine中。
2.函数返回成功，FullImageName的内存由调用者释放。
3.

用法示例：
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
        此时，FileFullName会有几种不同的表现形式，这应该在VISTA之前出现。
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
            LoadImageFullName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, LoadImageFullName->MaximumLength, TAG);//由调用者释放。
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

没想到这个函数写于2012年，且是由汇编语言改编的。
*/
{
    KIRQL Irql = KeRaiseIrqlToDpcLevel(); 

    PKLDR_DATA_TABLE_ENTRY DriverSection = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (NULL != DriverSection) {  //从驱动链表中摘除，隐藏驱动。
        //RemoveHeadList(&DriverSection->InLoadOrderLinks);

        *((SIZE_T *)DriverSection->InLoadOrderLinks.Blink) = (SIZE_T)DriverSection->InLoadOrderLinks.Flink;
        DriverSection->InLoadOrderLinks.Flink->Blink = DriverSection->InLoadOrderLinks.Blink;

        //这两句防止蓝屏。
        DriverSection->InLoadOrderLinks.Flink = (PLIST_ENTRY)&(DriverSection->InLoadOrderLinks.Flink);
        DriverSection->InLoadOrderLinks.Blink = (PLIST_ENTRY)&(DriverSection->InLoadOrderLinks.Flink);

        ////隐藏驱动的全路径。隐藏这两项重新加载可能有点问题。
        //DriverSection->FullDllName.Length = 0;
        //DriverSection->FullDllName.MaximumLength = 0;
        //DriverSection->FullDllName.Buffer = 0;

        ////隐藏驱动的文件名。
        //DriverSection->BaseDllName.Length = 0;
        //DriverSection->BaseDllName.MaximumLength = 0;
        //DriverSection->BaseDllName.Buffer = 0;

        //别的项在这里隐藏会蓝屏哟！
    }

    KeLowerIrql(Irql);
}
