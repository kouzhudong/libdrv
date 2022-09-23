#include "pe.h"
#include "Image.h"
#include "Process.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


bool IsValidPE(_In_ PVOID Data)
{
    bool ret = false;

    __try {
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Data;
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            __leave;
        }

        PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(Data);
        switch (NtHeader->Signature) {
        case IMAGE_OS2_SIGNATURE:
            //LOGA(ERROR_LEVEL, "��ϲ��:����һ��NE�ļ�!");
            break;
        case IMAGE_OS2_SIGNATURE_LE://IMAGE_VXD_SIGNATURE
            //LOGA(ERROR_LEVEL, "��ϲ��:����һ��LE�ļ�!");
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
            //LOGA(ERROR_LEVEL, "��ϲ��:����һ��NE�ļ�!");
            __leave;
        }

        if (IMAGE_OS2_SIGNATURE_LE == other) //IMAGE_VXD_SIGNATURE
        {
            //LOGA(ERROR_LEVEL, "��ϲ��:����һ��LE�ļ�!");
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
    PIMAGE_DOS_HEADER DosHeader;
    SIZE_T  ntSignature;
    SIZE_T  CoffHeaderOffset;
    PIMAGE_FILE_HEADER FileHeader;
    PIMAGE_OPTIONAL_HEADER OptionalHeader;

    __try {
        DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            return FALSE;
        }

        ntSignature = (SIZE_T)DosHeader + DosHeader->e_lfanew;//��64λϵͳ�ϼ��WOW4����
        ntSignature = *(ULONG *)ntSignature;
        if (IMAGE_NT_SIGNATURE != ntSignature) {
            return FALSE;
        }

        CoffHeaderOffset = (SIZE_T)DosHeader + DosHeader->e_lfanew + sizeof(ULONG);
        FileHeader = (PIMAGE_FILE_HEADER)CoffHeaderOffset;

        /*
        ���ڿ�ѡͷ�ı�׼����˵����32λ�Ŀ�ѡͷ��64λ�Ŀ�ѡͷ����ν����Ϊƫ�ƶ���һ���ġ�
        */
        OptionalHeader = (PIMAGE_OPTIONAL_HEADER)((SIZE_T)FileHeader + sizeof(IMAGE_FILE_HEADER));

        if (OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            //����һ����ͨ��PE�ļ�
        } else if (OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            isPe64File = TRUE;//����һ����PE32+�ļ�
        } else if (OptionalHeader->Magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC) {
            //����һ����ROMӳ��
        } else {
            //δ֪���ļ�����.
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    return isPe64File;
}


ULONG Rva2Offset(IN LPVOID Data, IN ULONG Rva)
/*
����0��ʾʧ�ܣ������������ļ��е�ƫ�ơ�
*/
{
    ULONG Offset = 0;//����ֵ��
    IMAGE_FILE_HEADER * FileHeader = NULL;
    IMAGE_SECTION_HEADER * SectionHeader = NULL;
    USHORT i = 0;

    IMAGE_DOS_HEADER * DosHeader = (IMAGE_DOS_HEADER *)Data;
    if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
        return 0;
    }

    FileHeader = (IMAGE_FILE_HEADER *)((SIZE_T)DosHeader->e_lfanew + sizeof(ULONG) + (SIZE_T)Data);

    SectionHeader = (IMAGE_SECTION_HEADER *)((ULONG)(ULONG)DosHeader->e_lfanew + 
                                                      sizeof(ULONG) + 
                                                      sizeof(IMAGE_FILE_HEADER) + 
                                                      FileHeader->SizeOfOptionalHeader);//�����(ULONG),��Ȼ����.
    
    SectionHeader = (IMAGE_SECTION_HEADER *)((SIZE_T)SectionHeader + (SIZE_T)Data);

    for (; i < FileHeader->NumberOfSections; i++) //�淶�涨�Ǵ�1��ʼ��.
    {
        if (Rva >= SectionHeader[i].VirtualAddress && Rva <= 
            (SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize)) {
            Offset = Rva - SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData;
            break;
        }
    }

    return Offset;
}


UINT Rva2Va(_In_ PBYTE Data, _In_ UINT Rva)
/*
����0��ʾʧ�ܣ������������ļ��е�ƫ�ơ�
*/
{
    UINT Offset = 0;//����ֵ��

    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(Data);
    PIMAGE_FILE_HEADER FileHeader = (PIMAGE_FILE_HEADER)&NtHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER OptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeader->OptionalHeader;
    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)
        ((PBYTE)OptionalHeader + FileHeader->SizeOfOptionalHeader);

    //ע�⣺�и����IMAGE_FIRST_SECTION��

    for (WORD i = 0; i < FileHeader->NumberOfSections; i++) {
        if (Rva >= SectionHeader[i].VirtualAddress && 
            Rva <= SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize) {
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
�˺��������ڻ�ȡֻӳ��(map)��û�м���(load)���е���������PE�ļ��ĺ�����ַ�Ļ�ȡ��
*/
{
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG High;
    LONG Low;
    LONG Middle;
    LONG Result;
    ULONG ExportSize;
    PVOID FunctionAddress = 0;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    ULONG Rva;
    ULONG Offset;

    PAGED_CODE();

    __try {
        FunctionAddress = *(PVOID *)DllBase;
        FunctionAddress = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FunctionAddress;
    }

    //ȷ��DllBase���Է��ʡ�����������
    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase, 
                                                                            TRUE, 
                                                                            IMAGE_DIRECTORY_ENTRY_EXPORT,
                                                                            &ExportSize);
    if (ExportDirectory == NULL) {
        return NULL;
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
        PCHAR p = NULL;

        Middle = (Low + High) >> 1;// Compute the next probe index and compare the import name with the export name entry.

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
        return NULL;
    }

    OrdinalNumber = NameOrdinalTableBase[Middle];// + ExportDirectory->Base

    // If the OrdinalNumber is not within the Export Address Table,then this image does not implement the function.
    // Return not found.
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
        return NULL;
    }

    // Index into the array of RVA export addresses by ordinal number.
    Offset = Rva2Offset(DllBase, ExportDirectory->AddressOfFunctions);
    Addr = (PULONG)((PCHAR)DllBase + Offset);

    Offset = Rva2Offset(DllBase, Addr[OrdinalNumber]);
    FunctionAddress = (PVOID)((PCHAR)DllBase + Offset);

    // Forwarders are not used by the kernel and HAL to each other.
    ASSERT((FunctionAddress <= (PVOID)ExportDirectory) || 
           (FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

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
д��Ŀ�ģ�
MmGetSystemRoutineAddress������������µ����ƣ�
It can only be used for routines exported by the kernel or HAL, not for any driver-defined routine.

FltGetRoutineAddress������������µ����ƣ�
1.���õĺ�����
2.�Ǹ�ģ������Ѿ����ء�

NdisGetRoutineAddress�����Ƶ����ơ�

��ʱ���ȡ����ں�ģ��ĺ����ĵ�ַ��һ���������İ취���磺WINHV.sys��
����Ϊ�˻�ר��д�˺�������Ȼ�ǽ���PE32/PE32+�ˡ�

��ʵϵͳ�Ѿ��ṩ��һЩ������ֻ����������û�й������ѡ�

��WRK֪��:MmGetSystemRoutineAddress��ͨ��MiFindExportedRoutineByNameʵ�ֵġ�
���ǣ�MiFindExportedRoutineByNameû�е�������λ��û�кõ��ȶ��İ취��
�����Լ�ʵ�֣�����RtlImageDirectoryEntryToData��RtlImageNtHeader���Ѿ�������

���ĵ�һЩ��Ϣժ�ԣ�WRK��
������Ҳ��Դ�룬��������Ҳ�ǿ���ʹ�õġ�

made by correy
made at 2014.08.18
*/
{
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG High;
    LONG Low;
    LONG Middle;
    LONG Result;
    ULONG ExportSize;
    PVOID FunctionAddress = 0;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;

    PAGED_CODE();

    __try {
        FunctionAddress = *(PVOID *)DllBase;
        FunctionAddress = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FunctionAddress;
    }

    //ȷ��DllBase���Է��ʡ�����������
    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase,
                                                                            TRUE,
                                                                            IMAGE_DIRECTORY_ENTRY_EXPORT,
                                                                            &ExportSize);
    if (ExportDirectory == NULL) {
        return NULL;
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
        return NULL;
    }

    OrdinalNumber = NameOrdinalTableBase[Middle];

    // If the OrdinalNumber is not within the Export Address Table,then this image does not implement the function.
    // Return not found.
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
        return NULL;
    }

    // Index into the array of RVA export addresses by ordinal number.
    Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);
    FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);

    // Forwarders are not used by the kernel and HAL to each other.
    ASSERT((FunctionAddress <= (PVOID)ExportDirectory) ||
           (FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

    return FunctionAddress;
}


NTSTATUS WINAPI GetUserFunctionAddress(_In_ PVOID DllBase,
                                       _In_ PUNICODE_STRING FullDllName,
                                       _In_opt_ PVOID Context
)
/*
ö���û�ģ��Ļص�������

ע�⣺˫����DLL·����ȫ·���Ҹ�ʽһ�¡�
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (NULL == Context || NULL == DllBase) {
        return status;
    }

    if (NULL == FullDllName || NULL == FullDllName->Buffer) {
        return status;
    }

    PGetUserFunctionAddressInfo UserFunctionAddress = (PGetUserFunctionAddressInfo)Context;

    UNICODE_STRING DllFullName = {0};
    RtlInitUnicodeString(&DllFullName, UserFunctionAddress->DllFullName);

    if (0 != RtlCompareUnicodeString(FullDllName, &DllFullName, TRUE)) {
        return status;
    }

    ANSI_STRING FunctionName = {0};
    RtlInitAnsiString(&FunctionName, UserFunctionAddress->FunctionName);

    UserFunctionAddress->UserFunctionAddress = MiFindExportedRoutineByName(DllBase, &FunctionName);
    if (UserFunctionAddress->UserFunctionAddress) {
        status = STATUS_SUCCESS;
    } 

    return status;
}


PVOID GetUserFunctionAddress(_In_ HANDLE ProcessId, _In_ PWSTR DllFullName, _In_ PSTR FunctionName)
/*
���ܣ���ȡĳ�����̵�ĳ��ģ���ĳ��(����)�����ĵ�ַ��

����˵����
DllFullName��ģ���ȫ·����

ע�ͣ�֮������ȫ·��������Ϊһ�����̿��ܼ���������ͬ���ֵ�ģ�飬��WOW64����������ntdll.dll��
*/
{
    GetUserFunctionAddressInfo UserFunctionAddress = {0};

    RtlStringCchCopyW(UserFunctionAddress.DllFullName, ARRAYSIZE(UserFunctionAddress.DllFullName), DllFullName);
    RtlStringCchCopyA(UserFunctionAddress.FunctionName, ARRAYSIZE(UserFunctionAddress.FunctionName), FunctionName);

    EnumUserModule(ProcessId, GetUserFunctionAddress, &UserFunctionAddress);

    return UserFunctionAddress.UserFunctionAddress;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL ModifyPe32Entry(_In_ PVOID ImageBase) //�����̵ģ�������bool��true.
/*
�˰취��DLL��SYS��EXE����Ч
ע�⣺DLL�������ķ���ֵ�ǲ�һ���ġ�

��ʱ�����Ѿ����أ�����û�����С�
�������������������дc20800��ret 8��ע�Ͳ��ǣ�retn�Ļ�����c3.
����Ҫ��дmov eax,STATUS_UNSUCCESSFUL�Ļ������ˡ�#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
wdk����������������ӵģ�����������ڣ����д��������ڲ�����������ڣ�����������pe�ļ�����ں�DriverEntry�Ĺ�ϵ��
*/
{
    PIMAGE_DOS_HEADER DosHeader;
    SIZE_T  ntSignature;
    SIZE_T  CoffHeaderOffset;
    PIMAGE_FILE_HEADER FileHeader;
    PIMAGE_OPTIONAL_HEADER32 OptionalHeader;
    SIZE_T AddressOfEntryPoint;
    int x;
    PMDL pmdl;
    PSIZE_T EntryPoint;

    //B8 00 00 00 00     mov     eax, 000000000h
    //c20c00             ret c   ��ʵ�����ֹ��DLL������EXE�������ļ�����ڶ���û�в����ġ�
    unsigned char opcode[] = {0xB8,0x00,0x00,0x00,0x00,0xc2,0x0c,0x00};

    __try {
        DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            return FALSE;
        }

        ntSignature = (SIZE_T)DosHeader + DosHeader->e_lfanew;//��64λϵͳ�ϼ��WOW4����
        ntSignature = *(ULONG *)ntSignature;
        if (IMAGE_NT_SIGNATURE != ntSignature) {
            return FALSE;
        }

        CoffHeaderOffset = (SIZE_T)DosHeader + DosHeader->e_lfanew + sizeof(ULONG);
        FileHeader = (PIMAGE_FILE_HEADER)CoffHeaderOffset;

        /*
        ���ڿ�ѡͷ�ı�׼����˵����32λ�Ŀ�ѡͷ��64λ�Ŀ�ѡͷ����ν����Ϊƫ�ƶ���һ���ġ�
        */
        OptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((SIZE_T)FileHeader + sizeof(IMAGE_FILE_HEADER));

        AddressOfEntryPoint = OptionalHeader->AddressOfEntryPoint + (SIZE_T)ImageBase;

        /*
        ����������Ǻ��б�Ҫ�ģ�
        1.�����쳣������������ٷ�����
        2.���Բ鿴���ݡ�
        3.ӦΪ�ڴ���ʹ��ˣ����Ե���MmBuildMdlForNonPagedPool����������
        */
        x = *(int *)AddressOfEntryPoint;
        x = 0;

        pmdl = IoAllocateMdl((PVOID)AddressOfEntryPoint, 8, 0, 0, NULL);
        if (!pmdl) {
            return FALSE;
        }

        MmBuildMdlForNonPagedPool(pmdl);//���AddressOfEntryPoint����Ч�ڴ棬�����������
        //pmdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

#pragma prefast(push)
#pragma prefast(disable: 28145, "The opaque MDL structure should not be modified by a driver.")
        ClearFlag(pmdl->MdlFlags,
                  MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL | MDL_PARTIAL_HAS_BEEN_MAPPED);
        SetFlag(pmdl->MdlFlags, MDL_PAGES_LOCKED);
#pragma prefast(pop)        

        EntryPoint = (PSIZE_T)MmMapLockedPagesSpecifyCache(pmdl,
                                                           KernelMode,
                                                           MmCached,
                                                           NULL,
                                                           FALSE,
                                                           NormalPagePriority);
        ASSERT(EntryPoint);

#pragma prefast(push)
#pragma prefast(disable: 6386, "д�뵽��EntryPoint��ʱ���������: ��д��СΪ��_Param_(1)->ByteCount�����ֽڣ�������д���ˡ�8�����ֽ�")
        ASSERT(pmdl->ByteCount >= 8);
        RtlCopyMemory(EntryPoint, opcode, 8);
#pragma prefast(pop)          

        MmUnmapLockedPages(EntryPoint, pmdl);
        IoFreeMdl(pmdl);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    return FALSE;
}


BOOL ModifyPe64Entry(_In_ PVOID ImageBase)
/*
�˰취��DLL��SYS��EXE����Ч
ע�⣺DLL�������ķ���ֵ�ǲ�һ���ġ�

�������������������дretn�Ļ�����c3.
*/
{
    PIMAGE_DOS_HEADER DosHeader;
    SIZE_T  ntSignature;
    SIZE_T  CoffHeaderOffset;
    PIMAGE_FILE_HEADER FileHeader;
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader;
    SIZE_T AddressOfEntryPoint;
    int x;
    PMDL pmdl;
    PSIZE_T EntryPoint;

    //B8 00 00 00 00     mov     eax, 000000000h
    //c3                 retn
    unsigned char opcode[] = {0xB8,0x00,0x00,0x00,0x00,0xc3};

    __try {
        DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        if (IMAGE_DOS_SIGNATURE != DosHeader->e_magic) {
            return TRUE;
        }

        ntSignature = (SIZE_T)DosHeader + DosHeader->e_lfanew;//��64λϵͳ�ϼ��WOW4����
        ntSignature = *(ULONG *)ntSignature;
        if (IMAGE_NT_SIGNATURE != ntSignature) {
            return TRUE;
        }

        CoffHeaderOffset = (SIZE_T)DosHeader + DosHeader->e_lfanew + sizeof(ULONG);
        FileHeader = (PIMAGE_FILE_HEADER)CoffHeaderOffset;

        /*
        ���ڿ�ѡͷ�ı�׼����˵����32λ�Ŀ�ѡͷ��64λ�Ŀ�ѡͷ����ν����Ϊƫ�ƶ���һ���ġ�
        */
        OptionalHeader = (PIMAGE_OPTIONAL_HEADER64)((SIZE_T)FileHeader + sizeof(IMAGE_FILE_HEADER));

        AddressOfEntryPoint = OptionalHeader->AddressOfEntryPoint + (SIZE_T)ImageBase;

        /*
        ����������Ǻ��б�Ҫ�ģ�
        1.�����쳣������������ٷ�����
        2.���Բ鿴���ݡ�
        3.ӦΪ�ڴ���ʹ��ˣ����Ե���MmBuildMdlForNonPagedPool����������
        */
        x = *(int *)AddressOfEntryPoint;
        x = 0;

        //�е�����������д������32�ı��У�������ȷ��һЩ��ɾ��ֻ�����ԡ�
        pmdl = IoAllocateMdl((PVOID)AddressOfEntryPoint, 6, 0, 0, NULL);
        if (!pmdl) {
            return TRUE;
        }

        MmBuildMdlForNonPagedPool(pmdl);//���AddressOfEntryPoint����Ч�ڴ棬�����������
        //pmdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

#pragma prefast(push)
#pragma prefast(disable: 28145, "The opaque MDL structure should not be modified by a driver.")
        ClearFlag(pmdl->MdlFlags,
                  MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL | MDL_PARTIAL_HAS_BEEN_MAPPED);
        SetFlag(pmdl->MdlFlags, MDL_PAGES_LOCKED);
#pragma prefast(pop)        

        //WIN10��֤���»���ϵͳ�Ķ��ԣ�˵specified an executable MDL mapping��
        EntryPoint = (PSIZE_T)MmMapLockedPagesSpecifyCache(pmdl,
                                                           KernelMode,
                                                           MmCached,
                                                           NULL,
                                                           FALSE,
                                                           NormalPagePriority);
        ASSERT(EntryPoint);

#pragma prefast(push)
#pragma prefast(disable: 6386, "д�뵽��EntryPoint��ʱ���������: ��д��СΪ��_Param_(1)->ByteCount�����ֽڣ�������д���ˡ�6�����ֽڡ�")
        ASSERT(pmdl->ByteCount >= 6);
        RtlCopyMemory((PSIZE_T)EntryPoint, opcode, 6);//��ʵֱ�Ӹ�ֵҲ���ԡ�
#pragma prefast(pop)            

        MmUnmapLockedPages((PVOID)EntryPoint, pmdl);
        IoFreeMdl(pmdl);
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    return TRUE;
}


VOID ModifyPeEntry(_In_ PVOID ImageBase)
/*
�������������ж��ǲ�����ЧPE�ļ���ʽ�Ĺ��ܡ�
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


BOOLEAN ExtraFile(_In_ PCSTR FileName,
                  _In_ ULONG_PTR Type,
                  _In_ ULONG_PTR Id,
                  _In_ PUNICODE_STRING NewFileName
)
/*
���ܣ����������ͷ���Դ��Ϣ���ļ���

����˵����
FileName����Դ���ڵ��ļ��������������ļ���
Type����Դ�����ͣ���Ӧ�ò㶨���RT_��ͷ��RT_RCDATA֮������ݡ�
Id����Դ�ı�ʶ��
NewFileName�����ļ������֣��磺"\Device\HarddiskVolume1\XXX����\\??\\c:\\WINDOWS\\system32\\config\\SAM��
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob;
    HANDLE DestinationFileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    ULONG CreateDisposition = 0;
    LARGE_INTEGER ByteOffset = {0};
    LARGE_INTEGER AllocationSize = {0};
    PVOID BaseAddress = 0;

    ULONG_PTR ResourceIdPath[3];
    PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry = NULL;
    PVOID  MessageData;
    ULONG Size = 0;

    //�½��ļ�.
    CreateDisposition = FILE_OPEN_IF;// FILE_OPEN_IF FILE_OVERWRITE_IF FILE_SUPERSEDE;
    InitializeObjectAttributes(&ob, NewFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    status = ZwCreateFile(&DestinationFileHandle,
                          FILE_ALL_ACCESS | SYNCHRONIZE,
                          &ob,
                          &IoStatusBlock,
                          &AllocationSize,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_WRITE,
                          CreateDisposition,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    ASSERT(NT_SUCCESS(status));

    BaseAddress = GetImageBase(FileName);//�����ZwMapViewOfSection�ȼ���������û���õġ�

    ResourceIdPath[0] = Type;
    ResourceIdPath[1] = Id;
    ResourceIdPath[2] = 0;
    status = LdrFindResource_U(BaseAddress, ResourceIdPath, 3, &ResourceDataEntry);//��ZwMapViewOfSection����c000008a
    ASSERT(NT_SUCCESS(status));
    status = LdrAccessResource(BaseAddress, ResourceDataEntry, &MessageData, &Size);
    ASSERT(NT_SUCCESS(status));

    //���Ҫ�������4G��������Ӹ�ѭ������������4G������Ҳ����ӳ��ɹ���
    status = ZwWriteFile(DestinationFileHandle,
                         NULL,
                         NULL,
                         NULL,
                         &IoStatusBlock,
                         MessageData,
                         Size,
                         &ByteOffset,
                         NULL);
    ASSERT(NT_SUCCESS(status));

    ZwClose(DestinationFileHandle);
    return TRUE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS NTAPI IsFilePe64(_In_ PVOID ViewBase, _In_ SIZE_T ViewSize, _In_opt_ PVOID Context)
/*
MapViewOfSection�Ļص����������ڼ��PE��ʽ��
*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(ViewSize);

    BOOL ret = IsPe64(ViewBase);

    if (Context) {
        PBOOL temp = (PBOOL)Context;
        *temp = ret;
    }

    return Status;
}


BOOL IsFilePe64(_In_ PUNICODE_STRING ImageFileName)
/*
���ܣ��ж�һ��PE��ʽ���ļ��ǲ���PE32+��
*/
{
    BOOL ret = false;

    MapViewOfSection(ImageFileName, IsFilePe64, &ret);

    return ret;
}


BOOL IsProcessPe64(_In_ HANDLE UniqueProcess)
/*
���ܣ��ж�һ�������ǲ���64λ�ġ�

ʵ�ְ취���������ļ���Ӧ���ļ���PE��ʽ�����ǻ����İ취��

���еı�ļ��취���磺�ڴ�ȣ���Щ�취Ҳ����򵥺͸�Ч��
*/
{
    BOOL ret = false;
    PUNICODE_STRING ImageFileName = NULL;

    if (!GetFullNtProcessImageFileName(UniqueProcess, &ImageFileName)) {
        return false;
    }

    ret = IsFilePe64(ImageFileName);

    ExFreePoolWithTag((PVOID)ImageFileName, TAG);

    return ret;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
