#include "pe.h"
#include "Image.h"
#include "Process.h"
#include "Memory.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


bool IsValidPE(_In_ PVOID Data)
{
    bool ret = false;

    __try {
        PIMAGE_DOS_HEADER DosHeader = static_cast<PIMAGE_DOS_HEADER>(Data);
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            __leave;
        }

        PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(Data); //不是有效的PE，这里会崩溃，应用层也是。
        switch (NtHeader->Signature) {
        case IMAGE_OS2_SIGNATURE:
            //LOGA(ERROR_LEVEL, "恭喜你:发现一个NE文件!");
            break;
        case IMAGE_OS2_SIGNATURE_LE: //IMAGE_VXD_SIGNATURE
            //LOGA(ERROR_LEVEL, "恭喜你:发现一个LE文件!");
            break;
        case IMAGE_NT_SIGNATURE:
            ret = true;
            break;
        default:
            //LOGA(ERROR_LEVEL, "Signature:%X", nt_headers->Signature);
            break;
        }

    #if 0
        ULONG  ntSignature = (ULONG)dos_header + dos_header->e_lfanew;
        unsigned short int other = *(unsigned short int *)ntSignature;
        ntSignature = *(ULONG *)ntSignature;

        if (IMAGE_OS2_SIGNATURE == other) {
            //LOGA(ERROR_LEVEL, "恭喜你:发现一个NE文件!");
            __leave;
        }

        if (IMAGE_OS2_SIGNATURE_LE == other) //IMAGE_VXD_SIGNATURE
        {
            //LOGA(ERROR_LEVEL, "恭喜你:发现一个LE文件!");
            __leave;
        }

        if (IMAGE_NT_SIGNATURE == ntSignature) {
            ret = true;
        }
    #endif // 0
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ret = GetExceptionCode();
        ///LOGA(ERROR_LEVEL, "ExceptionCode:%#x", ret);
    }

    return ret;
}


BOOL IsPe64(_In_ PVOID ImageBase)
{
    BOOL isPe64File = FALSE;
    PIMAGE_DOS_HEADER DosHeader{};
    SIZE_T ntSignature{};
    SIZE_T CoffHeaderOffset{};
    PIMAGE_FILE_HEADER FileHeader{};
    PIMAGE_OPTIONAL_HEADER OptionalHeader{};

    __try {
        DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            return FALSE;
        }

        ntSignature = (SIZE_T)DosHeader + DosHeader->e_lfanew; //在64位系统上检查WOW4程序。
        ntSignature = *(ULONG *)ntSignature;
        if (IMAGE_NT_SIGNATURE != ntSignature) {
            return FALSE;
        }

        CoffHeaderOffset = (SIZE_T)DosHeader + DosHeader->e_lfanew + sizeof(ULONG);
        FileHeader = (PIMAGE_FILE_HEADER)CoffHeaderOffset;

        /*
        对于可选头的标准域来说，是32位的可选头和64位的可选头无所谓，因为偏移都是一样的。
        */
        OptionalHeader = (PIMAGE_OPTIONAL_HEADER)((SIZE_T)FileHeader + sizeof(IMAGE_FILE_HEADER));

        if (OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            //这是一个普通的PE文件
        } else if (OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            isPe64File = TRUE; //这是一个的PE32+文件
        } else if (OptionalHeader->Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC) {
            //这是一个的ROM映像
        } else {
            //未知的文件类型.
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    return isPe64File;
}


ULONG Rva2Offset(IN LPVOID Data, IN ULONG Rva)
/*
返回0表示失败，其他的是在文件中的偏移。
*/
{
    ULONG Offset = 0; //返回值。
    IMAGE_FILE_HEADER * FileHeader = nullptr;
    IMAGE_SECTION_HEADER * SectionHeader = nullptr;
    USHORT i = 0;

    IMAGE_DOS_HEADER * DosHeader = static_cast<IMAGE_DOS_HEADER *>(Data);
    if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
        return 0;
    }

    FileHeader = reinterpret_cast<IMAGE_FILE_HEADER *>(static_cast<SIZE_T>(DosHeader->e_lfanew) + sizeof(ULONG) + reinterpret_cast<SIZE_T>(Data));

    SectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER *>(static_cast<ULONG>(DosHeader->e_lfanew) +
                                                             sizeof(ULONG) +
                                                             sizeof(IMAGE_FILE_HEADER) +
                                                             FileHeader->SizeOfOptionalHeader); //必须加(ULONG),不然出错.

    SectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<SIZE_T>(SectionHeader) + reinterpret_cast<SIZE_T>(Data));

    for (; i < FileHeader->NumberOfSections; i++) //规范规定是从1开始的.
    {
        if (Rva >= SectionHeader[i].VirtualAddress && Rva <= (SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize)) {
            Offset = Rva - SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData;
            break;
        }
    }

    return Offset;
}


UINT Rva2Va(_In_ PBYTE Data, _In_ UINT Rva)
/*
返回0表示失败，其他的是在文件中的偏移。
*/
{
    UINT Offset = 0; //返回值。

    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(Data);
    PIMAGE_FILE_HEADER FileHeader = static_cast<PIMAGE_FILE_HEADER>(&NtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER OptionalHeader = static_cast<PIMAGE_OPTIONAL_HEADER>(&NtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER SectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(OptionalHeader) + FileHeader->SizeOfOptionalHeader);

    //注意：有个宏叫IMAGE_FIRST_SECTION。

    for (WORD i = 0; i < FileHeader->NumberOfSections; i++) {
        if (Rva >= SectionHeader[i].VirtualAddress && Rva <= SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize) {
            Offset = Rva - SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData;
            break;
        }
    }

    return Offset;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


PVOID MiFindExportedRoutineByNameEx(_In_ PVOID DllBase, _In_ PANSI_STRING AnsiImageRoutineName)
/*++
Routine Description:
    This function searches the argument module looking for the requested exported function name.
Arguments:
    DllBase - Supplies the base address of the requested module.
    AnsiImageRoutineName - Supplies the ANSI routine name being searched for.
Return Value:
    The virtual address of the requested routine or NULL if not found.
--*/
/*
此函数适用于获取只映射(map)而没有加载(load)的有导出函数的PE文件的函数地址的获取。
*/
{
    USHORT OrdinalNumber{};
    PULONG NameTableBase{};
    PUSHORT NameOrdinalTableBase{};
    PULONG Addr{};
    LONG High{};
    LONG Low{};
    LONG Middle{};
    LONG Result{};
    ULONG ExportSize{};
    PVOID FunctionAddress{};
    PIMAGE_EXPORT_DIRECTORY ExportDirectory{};
    ULONG Rva{};
    ULONG Offset{};

    PAGED_CODE();

    __try {
        FunctionAddress = *(PVOID *)DllBase;
        FunctionAddress = nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FunctionAddress;
    }

    //确保DllBase可以访问。否则蓝屏。
    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportSize);
    if (ExportDirectory == nullptr) {
        return nullptr;
    }

    Rva = (ULONG)((SIZE_T)ExportDirectory - (SIZE_T)DllBase);
    Offset = Rva2Offset(DllBase, Rva);
    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((SIZE_T)DllBase + Offset);

    Offset = Rva2Offset(DllBase, ExportDirectory->AddressOfNames);
    NameTableBase = (PULONG)((SIZE_T)DllBase + Offset);

    Offset = Rva2Offset(DllBase, ExportDirectory->AddressOfNameOrdinals);
    NameOrdinalTableBase = (PUSHORT)((SIZE_T)DllBase + Offset);

    Low = 0;
    Middle = 0;
    High = ExportDirectory->NumberOfNames - 1;

    while (High >= Low) // Lookup the desired name in the name table using a binary search.
    {
        SIZE_T temp = 0;
        PCHAR p = nullptr;

        Middle = (Low + High) >> 1; // Compute the next probe index and compare the import name with the export name entry.

        Offset = Rva2Offset(DllBase, NameTableBase[Middle]);
        temp = (SIZE_T)((SIZE_T)DllBase + Offset);
        p = (PCHAR)temp;

        Result = strcmp(AnsiImageRoutineName->Buffer, p);
        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            break;
        }
    }

    // If the high index is less than the low index, then a matching table entry was not found.
    // Otherwise, get the ordinal number from the ordinal table.
    if (High < Low) {
        return nullptr;
    }

    OrdinalNumber = NameOrdinalTableBase[Middle]; // + ExportDirectory->Base

    // If the OrdinalNumber is not within the Export Address Table,then this image does not implement the function.
    // Return not found.
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
        return nullptr;
    }

    // Index into the array of RVA export addresses by ordinal number.
    Offset = Rva2Offset(DllBase, ExportDirectory->AddressOfFunctions);
    Addr = (PULONG)((PCHAR)DllBase + Offset);

    Offset = Rva2Offset(DllBase, Addr[OrdinalNumber]);
    FunctionAddress = (PVOID)((PCHAR)DllBase + Offset);

    // Forwarders are not used by the kernel and HAL to each other.
    ASSERT((FunctionAddress <= (PVOID)ExportDirectory) || (FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

    return FunctionAddress;
}


PVOID MiFindExportedRoutineByName(_In_ PVOID DllBase, _In_ PANSI_STRING AnsiImageRoutineName)
/*++
Routine Description:
    This function searches the argument module looking for the requested exported function name.
Arguments:
    DllBase - Supplies the base address of the requested module.
    AnsiImageRoutineName - Supplies the ANSI routine name being searched for.
Return Value:
    The virtual address of the requested routine or NULL if not found.
--*/

/*
写作目的：
MmGetSystemRoutineAddress这个函数有如下的限制：
It can only be used for routines exported by the kernel or HAL, not for any driver-defined routine.

FltGetRoutineAddress这个函数有如下的限制：
1.调用的函数。
2.那个模块必须已经加载。

NdisGetRoutineAddress有类似的限制。

有时候获取别的内核模块的函数的地址是一个解决问题的办法，如：WINHV.sys。
有人为此还专门写了函数，当然是解析PE32/PE32+了。

其实系统已经提供了一些函数，只不过导出而没有公开而已。

看WRK知道:MmGetSystemRoutineAddress是通过MiFindExportedRoutineByName实现的。
可是：MiFindExportedRoutineByName没有导出，定位又没有好的稳定的办法。
所以自己实现，还好RtlImageDirectoryEntryToData（RtlImageNtHeader）已经导出。

本文的一些信息摘自：WRK。
不过这也是源码，加入驱动也是可以使用的。

注意：
如果是获取应用层的地址，需要附加到进程。

made by correy
made at 2014.08.18
*/
{
    USHORT OrdinalNumber{};
    PULONG NameTableBase{};
    PUSHORT NameOrdinalTableBase{};
    PULONG Addr{};
    LONG High{};
    LONG Low{};
    LONG Middle{};
    LONG Result{};
    ULONG ExportSize{};
    PVOID FunctionAddress{};
    PIMAGE_EXPORT_DIRECTORY ExportDirectory{};

    PAGED_CODE();

    __try {
        FunctionAddress = *(PVOID *)DllBase;
        FunctionAddress = nullptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FunctionAddress;
    }

    //确保DllBase可以访问。否则蓝屏。
    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportSize);
    if (ExportDirectory == nullptr) {
        return nullptr;
    }

    // Initialize the pointer to the array of RVA-based ansi export strings.
    NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);

    // Initialize the pointer to the array of USHORT ordinal numbers.
    NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

    Low = 0;
    Middle = 0;
    High = ExportDirectory->NumberOfNames - 1;

    while (High >= Low) // Lookup the desired name in the name table using a binary search.
    {
        // Compute the next probe index and compare the import name with the export name entry.
        Middle = (Low + High) >> 1;
        Result = strcmp(AnsiImageRoutineName->Buffer, (PCHAR)DllBase + NameTableBase[Middle]);
        if (Result < 0) {
            High = Middle - 1;
        } else if (Result > 0) {
            Low = Middle + 1;
        } else {
            break;
        }
    }

    // If the high index is less than the low index, then a matching table entry was not found.
    // Otherwise, get the ordinal number from the ordinal table.
    if (High < Low) {
        return nullptr;
    }

    OrdinalNumber = NameOrdinalTableBase[Middle];

    // If the OrdinalNumber is not within the Export Address Table,then this image does not implement the function.
    // Return not found.
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
        return nullptr;
    }

    // Index into the array of RVA export addresses by ordinal number.
    Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
    FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);

    // Forwarders are not used by the kernel and HAL to each other.
    ASSERT((FunctionAddress <= (PVOID)ExportDirectory) || (FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

    return FunctionAddress;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS WINAPI GetUserFunctionAddressByPeb(_In_ PVOID DllBase, _In_ PUNICODE_STRING FullDllName, _In_opt_ PVOID Context)
/*
枚举用户模块的回调函数。

注意：双方的DLL路径是全路径且格式一致。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (nullptr == Context || nullptr == DllBase) {
        return Status;
    }

    if (nullptr == FullDllName || nullptr == FullDllName->Buffer) {
        return Status;
    }

    PGetUserFunctionAddressInfo UserFunctionAddress = static_cast<PGetUserFunctionAddressInfo>(Context);

    UNICODE_STRING DllFullName{};
    RtlInitUnicodeString(&DllFullName, UserFunctionAddress->DllFullName);

    if (0 != RtlCompareUnicodeString(FullDllName, &DllFullName, TRUE)) {
        return Status;
    }

    ANSI_STRING FunctionName{};
    RtlInitAnsiString(&FunctionName, UserFunctionAddress->FunctionName);

    UserFunctionAddress->UserFunctionAddress = MiFindExportedRoutineByName(DllBase, &FunctionName);
    if (UserFunctionAddress->UserFunctionAddress) {
        Status = STATUS_SUCCESS;
    }

    return Status;
}


PVOID GetUserFunctionAddressByPeb(_In_ HANDLE ProcessId, _In_ PWSTR DllFullName, _In_ PSTR FunctionName)
/*
功能：获取某个进程的某个模块的某个(导出)函数的地址。

参数说明：
DllFullName：模块的全路径。

注释：之所以用全路径，是因为一个进程可能加载两个相同名字的模块，如WOW64进程有两个ntdll.dll。
*/
{
    GetUserFunctionAddressInfo UserFunctionAddress{};

    RtlStringCchCopyW(UserFunctionAddress.DllFullName, ARRAYSIZE(UserFunctionAddress.DllFullName), DllFullName);
    RtlStringCchCopyA(UserFunctionAddress.FunctionName, ARRAYSIZE(UserFunctionAddress.FunctionName), FunctionName);

    EnumUserModule(ProcessId, GetUserFunctionAddressByPeb, &UserFunctionAddress);

    return UserFunctionAddress.UserFunctionAddress;
}


NTSTATUS WINAPI GetUserFunctionAddress(_In_ HANDLE Pid, _In_ PMEMORY_BASIC_INFORMATION MemoryBasicInfo, _In_opt_ PVOID Context)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PEPROCESS Process = nullptr;
    HANDLE KernelHandle{};
    PGetUserFunctionAddressInfo UserFunctionAddress = static_cast<PGetUserFunctionAddressInfo>(Context);

    //\nt4\private\sdktools\psapi\mapfile.c
    struct {
        OBJECT_NAME_INFORMATION ObjectNameInfo;
        WCHAR FileName[1024]; //MAX_PATH 必须为1024，否则失败，原因看：ObQueryNameString。
    } s = {};

    __try {
        if (!MemoryBasicInfo || !UserFunctionAddress) {
            Status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        Status = PsLookupProcessByProcessId(Pid, &Process);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsProcessType, KernelMode, &KernelHandle);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        Status = GetMemoryMappedFilenameInformation(KernelHandle, MemoryBasicInfo->BaseAddress, &s.ObjectNameInfo, sizeof(s));
        if (!NT_SUCCESS(Status)) { //地址为0会返回STATUS_INVALID_ADDRESS。
            //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        //Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "FullDllName:%wZ\n", &s.ObjectNameInfo.Name);

        UNICODE_STRING DllFullName{};
        RtlInitUnicodeString(&DllFullName, UserFunctionAddress->DllFullName);
        if (0 != RtlCompareUnicodeString(&s.ObjectNameInfo.Name, &DllFullName, TRUE)) {
            Status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        KAPC_STATE ApcState;
        KeStackAttachProcess(Process, &ApcState);

        ANSI_STRING FunctionName{};
        RtlInitAnsiString(&FunctionName, UserFunctionAddress->FunctionName);
        UserFunctionAddress->UserFunctionAddress = MiFindExportedRoutineByName(MemoryBasicInfo->BaseAddress, &FunctionName);
        if (UserFunctionAddress->UserFunctionAddress) {
            Status = STATUS_SUCCESS; //结束上层的枚举。
        }

        KeUnstackDetachProcess(&ApcState);
    } __finally {
        if (KernelHandle) {
            ZwClose(KernelHandle);
        }

        if (Process) {
            ObDereferenceObject(Process);
        }
    }

    return Status;
}


PVOID GetUserFunctionAddress(_In_ HANDLE ProcessId, _In_ PWSTR DllFullName, _In_ PSTR FunctionName)
/*
功能：获取某个进程的某个模块的某个(导出)函数的地址。

参数说明：
DllFullName：模块的全路径。

注释：之所以用全路径，是因为一个进程可能加载两个相同名字的模块，如WOW64进程有两个ntdll.dll。
*/
{
    GetUserFunctionAddressInfo UserFunctionAddress{};

    RtlStringCchCopyW(UserFunctionAddress.DllFullName, ARRAYSIZE(UserFunctionAddress.DllFullName), DllFullName);
    RtlStringCchCopyA(UserFunctionAddress.FunctionName, ARRAYSIZE(UserFunctionAddress.FunctionName), FunctionName);

    EnumVirtualMemory(ProcessId, GetUserFunctionAddress, &UserFunctionAddress);

    return UserFunctionAddress.UserFunctionAddress;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL ModifyPe32Entry(_In_ PVOID ImageBase) //她奶奶的，不能用bool和true.
/*
此办法对DLL，SYS和EXE都有效
注意：DLL和驱动的返回值是不一样的。

此时驱动已经加载，但还没有运行。
做法是在驱动的入口填写c20800即ret 8。注释不是：retn的机器码c3.
不必要再写mov eax,STATUS_UNSUCCESSFUL的机器码了。#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
wdk编译的驱动入口是添加的，非真正的入口，汇编写的驱动入口才是真正的入口，这里的入口是pe文件的入口和DriverEntry的关系。
*/
{
    PIMAGE_DOS_HEADER DosHeader{};
    SIZE_T ntSignature{};
    SIZE_T CoffHeaderOffset{};
    PIMAGE_FILE_HEADER FileHeader{};
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader{};
    SIZE_T AddressOfEntryPoint{};
    int x{};
    PMDL pmdl{};
    PSIZE_T EntryPoint{};
    BOOL ret = FALSE;

    //B8 00 00 00 00     mov     eax, 000000000h
    //c20c00             ret c   其实这个不止是DLL，还有EXE，但是文件的入口都是没有参数的。
    unsigned char opcode[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xc2, 0x0c, 0x00};

    __try {
        DosHeader = static_cast<PIMAGE_DOS_HEADER>(ImageBase);
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            __leave;
        }

        ntSignature = reinterpret_cast<SIZE_T>(DosHeader) + DosHeader->e_lfanew; //在64位系统上检查WOW4程序。
        ntSignature = *reinterpret_cast<ULONG *>(ntSignature);
        if (IMAGE_NT_SIGNATURE != ntSignature) {
            __leave;
        }

        CoffHeaderOffset = reinterpret_cast<SIZE_T>(DosHeader) + DosHeader->e_lfanew + sizeof(ULONG);
        FileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(CoffHeaderOffset);

        /*
        对于可选头的标准域来说，是32位的可选头和64位的可选头无所谓，因为偏移都是一样的。
        */
        OptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(reinterpret_cast<SIZE_T>(FileHeader) + sizeof(IMAGE_FILE_HEADER));

        AddressOfEntryPoint = OptionalHeader->AddressOfEntryPoint + reinterpret_cast<SIZE_T>(ImageBase);

        /*
        这个操作还是很有必要的：
        1.触发异常。尽管这个很少发生。
        2.可以查看数据。
        3.应为内存访问过了，所以导致MmBuildMdlForNonPagedPool不会蓝屏。
        */
        x = *reinterpret_cast<int *>(AddressOfEntryPoint);
        x = 0;

        pmdl = IoAllocateMdl(reinterpret_cast<PVOID>(AddressOfEntryPoint), 8, 0, 0, nullptr);
        if (!pmdl) {
            __leave;
        }

        MmBuildMdlForNonPagedPool(pmdl); //如果AddressOfEntryPoint是无效内存，这里会蓝屏。
        //pmdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

    #pragma prefast(push)
    #pragma prefast(disable : 28145, "The opaque MDL structure should not be modified by a driver.")
        ClearFlag(pmdl->MdlFlags, MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL | MDL_PARTIAL_HAS_BEEN_MAPPED);
        SetFlag(pmdl->MdlFlags, MDL_PAGES_LOCKED);
    #pragma prefast(pop)

        EntryPoint = static_cast<PSIZE_T>(MmMapLockedPagesSpecifyCache(pmdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority));
        if (!EntryPoint) {
            __leave;
        }

    #pragma prefast(push)
    #pragma prefast(disable : 6386, "写入到“EntryPoint”时缓冲区溢出: 可写大小为“_Param_(1)->ByteCount”个字节，但可能写入了“8”个字节")
        ASSERT(pmdl->ByteCount >= 8);
        RtlCopyMemory(EntryPoint, opcode, 8);
    #pragma prefast(pop)

        ret = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    if (pmdl) {
        if (EntryPoint) {
            MmUnmapLockedPages(EntryPoint, pmdl);
        }

        IoFreeMdl(pmdl);
    }

    return ret;
}


BOOL ModifyPe64Entry(_In_ PVOID ImageBase)
/*
此办法对DLL，SYS和EXE都有效
注意：DLL和驱动的返回值是不一样的。

做法是在驱动的入口填写retn的机器码c3.
*/
{
    PIMAGE_DOS_HEADER DosHeader{};
    SIZE_T ntSignature{};
    SIZE_T CoffHeaderOffset{};
    PIMAGE_FILE_HEADER FileHeader{};
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader{};
    SIZE_T AddressOfEntryPoint{};
    int x{};
    PMDL pmdl{};
    PSIZE_T EntryPoint{};
    BOOL ret = FALSE;

    //B8 00 00 00 00     mov     eax, 000000000h
    //c3                 retn
    unsigned char opcode[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xc3};

    __try {
        DosHeader = static_cast<PIMAGE_DOS_HEADER>(ImageBase);
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            __leave;
        }

        ntSignature = reinterpret_cast<SIZE_T>(DosHeader) + DosHeader->e_lfanew; //在64位系统上检查WOW4程序。
        ntSignature = *reinterpret_cast<ULONG *>(ntSignature);
        if (IMAGE_NT_SIGNATURE != ntSignature) {
            __leave;
        }

        CoffHeaderOffset = reinterpret_cast<SIZE_T>(DosHeader) + DosHeader->e_lfanew + sizeof(ULONG);
        FileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(CoffHeaderOffset);

        /*
        对于可选头的标准域来说，是32位的可选头和64位的可选头无所谓，因为偏移都是一样的。
        */
        OptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(reinterpret_cast<SIZE_T>(FileHeader) + sizeof(IMAGE_FILE_HEADER));

        AddressOfEntryPoint = OptionalHeader->AddressOfEntryPoint + reinterpret_cast<SIZE_T>(ImageBase);

        /*
        这个操作还是很有必要的：
        1.触发异常。尽管这个很少发生。
        2.可以查看数据。
        3.应为内存访问过了，所以导致MmBuildMdlForNonPagedPool不会蓝屏。
        */
        x = *reinterpret_cast<int *>(AddressOfEntryPoint);
        x = 0;

        //有的驱动不可以写，比如32的冰刃，在这里确保一些，删除只读属性。
        pmdl = IoAllocateMdl(reinterpret_cast<PVOID>(AddressOfEntryPoint), 6, 0, 0, nullptr);
        if (!pmdl) {
            __leave;
        }

        MmBuildMdlForNonPagedPool(pmdl); //如果AddressOfEntryPoint是无效内存，这里会蓝屏。
        //pmdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

    #pragma prefast(push)
    #pragma prefast(disable : 28145, "The opaque MDL structure should not be modified by a driver.")
        ClearFlag(pmdl->MdlFlags, MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL | MDL_PARTIAL_HAS_BEEN_MAPPED);
        SetFlag(pmdl->MdlFlags, MDL_PAGES_LOCKED);
    #pragma prefast(pop)

        //WIN10验证器下会有系统的断言，说specified an executable MDL mapping。
        EntryPoint = reinterpret_cast<PSIZE_T>(MmMapLockedPagesSpecifyCache(pmdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority));
        if (!EntryPoint) {
            __leave;
        }

    #pragma prefast(push)
    #pragma prefast(disable : 6386, "XXXXX")
        ASSERT(pmdl->ByteCount >= 6);
        RtlCopyMemory((PSIZE_T)EntryPoint, opcode, 6); //其实直接赋值也可以。
    #pragma prefast(pop)

        ret = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    if (pmdl) {
        if (EntryPoint) {
            MmUnmapLockedPages(reinterpret_cast<PVOID>(EntryPoint), pmdl);
        }

        IoFreeMdl(pmdl);
    }

    return ret;
}


VOID ModifyPeEntry(_In_ PVOID ImageBase)
/*
这里有隐含的判断是不是有效PE文件格式的功能。
*/
{
    if (!IsValidPE(ImageBase)) {
        return;
    }

    if (IsPe64(ImageBase)) {
        ModifyPe64Entry(ImageBase);
    } else {
        ModifyPe32Entry(ImageBase);
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS ExtraFile(_In_ PCSTR FileName, _In_ ULONG_PTR Type, _In_ ULONG_PTR Id, _In_ PUNICODE_STRING NewFileName)
/*
功能：在驱动层释放资源信息到文件。

参数说明：
FileName：资源所在的文件，这里是驱动文件。
Type：资源的类型，即应用层定义的RT_开头的RT_RCDATA之类的数据。
Id：资源的标识。
NewFileName：新文件的名字，如："\Device\HarddiskVolume1\XXX或者\\??\\c:\\WINDOWS\\system32\\config\\SAM。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob{};
    HANDLE DestinationFileHandle{};
    IO_STATUS_BLOCK IoStatusBlock{};
    ULONG CreateDisposition = 0;
    LARGE_INTEGER ByteOffset{};
    LARGE_INTEGER AllocationSize{};
    PVOID BaseAddress{};

    ULONG_PTR ResourceIdPath[3]{};
    PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = nullptr;
    PVOID MessageData{};
    ULONG Size = 0;

    //新建文件.
    CreateDisposition = FILE_OPEN_IF; // FILE_OPEN_IF FILE_OVERWRITE_IF FILE_SUPERSEDE;
    InitializeObjectAttributes(&ob, NewFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    Status = ZwCreateFile(&DestinationFileHandle,
                          FILE_ALL_ACCESS | SYNCHRONIZE,
                          &ob,
                          &IoStatusBlock,
                          &AllocationSize,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          CreateDisposition,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          nullptr,
                          0);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return Status;
    }

    BaseAddress = GetImageBase(FileName); //上面的ZwMapViewOfSection等几个函数是没有用的。

    ResourceIdPath[0] = Type;
    ResourceIdPath[1] = Id;
    ResourceIdPath[2] = 0;
    Status = LdrFindResource_U(BaseAddress, ResourceIdPath, 3, &ResourceDataEntry); //用ZwMapViewOfSection返回c000008a
    ASSERT(NT_SUCCESS(Status));
    Status = LdrAccessResource(BaseAddress, ResourceDataEntry, &MessageData, &Size);
    ASSERT(NT_SUCCESS(Status));

    //如果要处理大于4G的数据请加个循环。不过大于4G的数据也很难映射成功。
    Status = ZwWriteFile(DestinationFileHandle, nullptr, nullptr, nullptr, &IoStatusBlock, MessageData, Size, &ByteOffset, nullptr);
    ASSERT(NT_SUCCESS(Status));

    ZwClose(DestinationFileHandle);
    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS NTAPI IsFilePe64(_In_ PVOID ViewBase, _In_ SIZE_T ViewSize, _In_opt_ PVOID Context)
/*
MapViewOfSection的回调函数，用于检查PE格式。
*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(ViewSize);

    BOOL ret = IsPe64(ViewBase);

    if (Context) {
        PBOOL temp = reinterpret_cast<PBOOL>(Context);
        *temp = ret;
    }

    return Status;
}


BOOL IsFilePe64(_In_ PUNICODE_STRING ImageFileName)
/*
功能：判断一个PE格式的文件是不是PE32+。
*/
{
    BOOL ret = false;

    MapViewOfSection(ImageFileName, IsFilePe64, &ret);

    return ret;
}


BOOL IsProcessPe64(_In_ HANDLE UniqueProcess)
/*
功能：判断一个进程是不是64位的。

实现办法：检查这个文件对应的文件的PE格式，这是基本的办法。

还有的别的检查办法，如：内存等，这些办法也许更简单和高效。
*/
{
    BOOL ret = false;
    PUNICODE_STRING ImageFileName = nullptr;

    if (!GetFullNtProcessImageFileName(UniqueProcess, &ImageFileName)) {
        return false;
    }

    ret = IsFilePe64(ImageFileName);

    ExFreePoolWithTag((PVOID)ImageFileName, TAG);

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS CALLBACK GetRoutineAddressCallBack(ULONG numberOfModules, PAUX_MODULE_EXTENDED_INFO modules, _In_opt_ PVOID Context)
/*
枚举内核模块（EnumAllKernelModule）的回调函数。

注释：此回调函数注册一次，调用一次。
*/
{
    PAUX_MODULE_EXTENDED_INFO ModuleInfo = static_cast<PAUX_MODULE_EXTENDED_INFO>(Context);
    if (!ModuleInfo) {
        return STATUS_UNSUCCESSFUL;
    }

    for (ULONG i = 0; i < numberOfModules; i++) {
        PUCHAR ModuleName = modules[i].FullPathName + modules[i].FileNameOffset;
        PVOID ImageBase = modules[i].BasicInfo.ImageBase;

        if (_strnicmp(reinterpret_cast<char const *>(ModuleInfo->FullPathName), reinterpret_cast<char const *>(ModuleName), AUX_KLIB_MODULE_PATH_LEN) == 0) {
            ModuleInfo->BasicInfo.ImageBase = ImageBase;
            break;
        }
    }

    return STATUS_SUCCESS;
}


_Must_inspect_result_
_IRQL_requires_max_(PASSIVE_LEVEL)
PVOID NTAPI GetRoutineAddress(_In_ PCSTR ModuleName, _In_ PCSTR RoutineName)
/*
功能：获取一些内核模块的导出的函数的地址。

原因：
1.一些导出，lib里没有导出信息的函数。
2.一些函数的导出序数有变动，导致驱动加载失败。
3.一些导出，但没有文档和头文件的函数。

排除场景：
1.nt函数，建议使用MmGetSystemRoutineAddress。
2.Fltmgr.sys的建议使用FltGetRoutineAddress。
3.Ndis.sys的建议使用NdisGetRoutineAddress。
*/
{
    PVOID RoutineAddress = nullptr;
    NTSTATUS Status = STATUS_SUCCESS;
    AUX_MODULE_EXTENDED_INFO ModuleInfo{}; //临时借用，不再自己定义结构了。最好是自己定义，里面可以是指针。

    strcpy_s((char *)ModuleInfo.FullPathName, AUX_KLIB_MODULE_PATH_LEN, ModuleName);
    Status = EnumKernelModule(GetRoutineAddressCallBack, &ModuleInfo);
    if (!NT_SUCCESS(Status) || !ModuleInfo.BasicInfo.ImageBase) {
        return RoutineAddress;
    }

    ANSI_STRING FunctionName{};
    RtlInitAnsiString(&FunctionName, RoutineName);

    RoutineAddress = MiFindExportedRoutineByName(ModuleInfo.BasicInfo.ImageBase, &FunctionName);

    return RoutineAddress;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
