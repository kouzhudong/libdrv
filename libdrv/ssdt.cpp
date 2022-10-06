#include "pch.h"
#include "ssdt.h"
#include "Process.h"
#include "thread.h"
#include "object.h"
#include "pe.h"
#include "Image.h"
#include "File.h"


volatile ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryFn;
volatile ZwTerminateThread_pfn ZwTerminateThreadFn;
volatile ZwCreateThreadExFn ZwCreateThreadEx;


//////////////////////////////////////////////////////////////////////////////////////////////////


int GetIndexByNameInMemory(PANSI_STRING NtRoutineName)
/*
���ܣ���ȡNTDLL.DLL���ZW������Index��

���ڵ������ǻ�ȡsmss.exe���̵�NTDLL.DLL��Ȼ�������
���������ȱ���ǣ�
1.��ϵͳ����ʱsmss.exe��û������
2.����NTDLL.DLL���ڴ���ܻᱳ�۸ģ���HOOK����������֤���Ĵ۸ġ�
3.

�Ľ��������ǣ�����NTDLL.DLL����ļ��������Լ����ڴ�ӳ��Ȼ�������
*/
{
    HANDLE ProcessId = NULL;
    PEPROCESS    Process;
    NTSTATUS     Status = STATUS_SUCCESS;
    KAPC_STATE   ApcState;
    PVOID DllBase = 0;
    PVOID FunctionAddress;
    int index = 0;

    Status = GetPidFromProcessName(L"smss.exe", &ProcessId);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(ProcessId);

    Status = PsLookupProcessByProcessId(ProcessId, &Process);//�õ�ָ������ID�Ľ��̻�����
    ASSERT(NT_SUCCESS(Status));

    KeStackAttachProcess(Process, &ApcState); //���ӵ�ǰ�̵߳�Ŀ����̿ռ���   

    DllBase = GetNtdllImageBase(Process);
    ASSERT(DllBase);

    FunctionAddress = MiFindExportedRoutineByName(DllBase, NtRoutineName);
    ASSERT(FunctionAddress);

    index = (*(PULONG)((PUCHAR)FunctionAddress + 4));

    KeUnstackDetachProcess(&ApcState);//�������

    ObDereferenceObject(Process);

    return index;
}


#if defined(_AMD64_) || defined(_IA64_) 


int GetIndexByName(PANSI_STRING NtRoutineName)
/*
���ܣ���ntdll.dll�л�ȡZw�����������š�

�����ǲο���Ϣ

windbg�е���Ϣ��
2: kd> uf ntdll!ZwCreateFile
ntdll!NtCreateFile:
00007ffe`415fd180 4c8bd1          mov     r10,rcx
00007ffe`415fd183 b855000000      mov     eax,55h
00007ffe`415fd188 f604250803fe7f01 test    byte ptr [SharedUserData+0x308 (00000000`7ffe0308)],1
00007ffe`415fd190 7503            jne     ntdll!NtCreateFile+0x15 (00007ffe`415fd195)  Branch

ntdll!NtCreateFile+0x12:
00007ffe`415fd192 0f05            syscall
00007ffe`415fd194 c3              ret

ntdll!NtCreateFile+0x15:
00007ffe`415fd195 cd2e            int     2Eh
00007ffe`415fd197 c3              ret

IDA�е���Ϣ��
.text:000000018009CA40                                              ; Exported entry 287. NtCreateFile
.text:000000018009CA40                                              ; Exported entry 1870. ZwCreateFile
.text:000000018009CA40
.text:000000018009CA40                                              ; =============== S U B R O U T I N E =======================================
.text:000000018009CA40
.text:000000018009CA40
.text:000000018009CA40                                                              public ZwCreateFile
.text:000000018009CA40                                              ZwCreateFile    proc near               ; CODE XREF: EtwpCreateFile+107��p
.text:000000018009CA40                                                                                      ; RtlpFileIsWin32WithRCManifest+E3��p ...
.text:000000018009CA40 4C 8B D1                                                     mov     r10, rcx        ; NtCreateFile
.text:000000018009CA43 B8 55 00 00 00                                               mov     eax, 55h ; 'U'
.text:000000018009CA48 F6 04 25 08 03 FE 7F 01                                      test    byte ptr ds:7FFE0308h, 1
.text:000000018009CA50 75 03                                                        jnz     short loc_18009CA55
.text:000000018009CA52 0F 05                                                        syscall                 ; Low latency system call
.text:000000018009CA54 C3                                                           retn
.text:000000018009CA55                                              ; ---------------------------------------------------------------------------
.text:000000018009CA55
.text:000000018009CA55                                              loc_18009CA55:                          ; CODE XREF: ZwCreateFile+10��j
.text:000000018009CA55 CD 2E                                                        int     2Eh             ; DOS 2+ internal - EXECUTE COMMAND
.text:000000018009CA55                                                                                      ; DS:SI -> counted CR-terminated command string
.text:000000018009CA57 C3                                                           retn
.text:000000018009CA57                                              ZwCreateFile    endp
.text:000000018009CA57
.text:000000018009CA57                                              ; ---------------------------------------------------------------------------
*/
{
    HANDLE ImageFileHandle;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Section;
    PVOID ViewBase;
    SIZE_T ViewSize;
    KAPC_STATE ApcState;
    NTSTATUS Status;
    HANDLE  Handle = 0;
    int index = -1;

    //////////////////////////////////////////////////////////////////////////////////////////////

    UNICODE_STRING NTDLL = RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\ntdll.dll");
    wchar_t NtNTDLL[MAX_PATH] = {0};
    UNICODE_STRING g_NtNTDLL = {0};
    wchar_t DosNTDLL[MAX_PATH] = {0};
    UNICODE_STRING g_DosNTDLL = {0};

    RtlInitUnicodeString(&g_NtNTDLL, NtNTDLL);
    g_NtNTDLL.MaximumLength = sizeof(NtNTDLL);
    RtlInitUnicodeString(&g_DosNTDLL, DosNTDLL);
    g_DosNTDLL.MaximumLength = sizeof(DosNTDLL);

    GetSystemRootPathName(&NTDLL, &g_NtNTDLL, &g_DosNTDLL);

    //////////////////////////////////////////////////////////////////////////////////////////////

    // Attempt to open the driver image itself.
    // If this fails, then the driver image cannot be located, so nothing else matters.
    InitializeObjectAttributes(&ObjectAttributes,
                               &NTDLL,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    Status = ZwOpenFile(&ImageFileHandle,
                        FILE_EXECUTE,//FILE_READ_DATA
                        &ObjectAttributes,
                        &IoStatus,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        0);
    if (!NT_SUCCESS(Status)) {
        return index;
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    Status = ZwCreateSection(&Section,
                             SECTION_MAP_EXECUTE,//SECTION_MAP_READ
                             &ObjectAttributes,
                             NULL,
                             PAGE_EXECUTE,//PAGE_READONLY
                             SEC_COMMIT,
                             ImageFileHandle);
    if (!NT_SUCCESS(Status)) {
        ZwClose(ImageFileHandle);
        return index;
    }

    ViewBase = NULL;
    ViewSize = 0;

    // Since callees are not always in the context of the system process, 
    // attach here when necessary to guarantee the driver load occurs in a known safe address space to prevent security holes.
    KeStackAttachProcess(PsInitialSystemProcess, &ApcState);

    Status = ObOpenObjectByPointer(PsInitialSystemProcess,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   GENERIC_READ,
                                   *PsProcessType,
                                   KernelMode,
                                   &Handle);
    ASSERT(NT_SUCCESS(Status));

    Status = ZwMapViewOfSection(Section, Handle, &ViewBase, 0L, 0L, NULL, &ViewSize, ViewShare, 0L, PAGE_EXECUTE);
    if (!NT_SUCCESS(Status)) {
        ZwClose(Handle);
        KeUnstackDetachProcess(&ApcState);
        ZwClose(Section);
        ZwClose(ImageFileHandle);
        return index;
    }

    __try {
        PVOID FunctionAddress = MiFindExportedRoutineByNameEx(ViewBase, NtRoutineName);
        ASSERT(FunctionAddress);
        index = (*(PULONG)((PUCHAR)FunctionAddress + 4));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    ZwUnmapViewOfSection(Handle, ViewBase);
    KeUnstackDetachProcess(&ApcState);
    ZwClose(Section);
    ZwClose(ImageFileHandle);
    ZwClose(Handle);
    return index;
}


SIZE_T GetZwRoutineAddressByName(PANSI_STRING ZwRoutineName)
/*
���ܣ���ȡX64��û�е�����Zw������
ע�ͣ�1.����Nt�ĺ������ж�Ӧ��Zw������
      2.�ڿ�������������֤���������ZwCreateFile��ֵ��nt!VfZwCreateFile��
      3.�ڿ�������������֤�����������MmGetSystemRoutineAddress��ȡ��ZwCreateFile��ֵҲ��nt!VfZwCreateFile��
      4.����ZwCreateFile�������ݱ��ɶ�������Ǹ���ַ�������ĵ�ַ������ǲ���ġ�
      5.MiFindExportedRoutineByName��ȡ�Ĳ���������ZwCreateFile��ַ��
*/
{
    SIZE_T p = 0;
    SIZE_T CreateFile = (SIZE_T)ZwCreateFile;
    SIZE_T CreateKey = (SIZE_T)ZwCreateKey;
    ANSI_STRING File = RTL_CONSTANT_STRING("ZwCreateFile");
    ANSI_STRING Key = RTL_CONSTANT_STRING("ZwCreateKey");
    int ZwCreateFileIndex = GetIndexByName(&File);
    int ZwCreateKeyIndex = GetIndexByName(&Key);
    int x = 0;
    SIZE_T y = 0;
    SIZE_T z = 0;
    SIZE_T base;
    int index = 0;
    LONG_PTR t = 0;

    if (-1 == ZwCreateFileIndex || -1 == ZwCreateKeyIndex) {
        return 0;
    }

    CreateFile = (SIZE_T)MiFindExportedRoutineByName(GetNtBase(), &File);
    CreateKey = (SIZE_T)MiFindExportedRoutineByName(GetNtBase(), &Key);

    if ((ZwCreateFileIndex - ZwCreateKeyIndex) > 0) {
        x = ZwCreateFileIndex - ZwCreateKeyIndex;
    } else {
        x = ZwCreateKeyIndex - ZwCreateFileIndex;
    }

    t = CreateFile - CreateKey;
    if (t > 0) {
        y = CreateFile - CreateKey;
    } else {
        y = CreateKey - CreateFile;
    }

    z = y / x;

    base = CreateFile - ZwCreateFileIndex * z;
    ASSERT(base == CreateKey - ZwCreateKeyIndex * z);

    /*
    ��Ϊ�е�ZW����û�����ں˵�������������Ҫ����NTDLL.DLL��
    */

    index = GetIndexByName(ZwRoutineName);

    p = base + index * z;

    return p;
}


#else


ULONG GetIndexOfSsdtFunction(PCSTR function_name)
/*
���ܣ���ȡSSDT�����ĵ��úš�
����֧���ں�û�е�����SSDT�ĺ�������ntoskrnl.exeû�е�������ntdll.dll�����ģ���SSDT���еĺ�����

windbg�ķ�����
0: kd> !process 0 0 smss.exe
PROCESS 93248840  SessionId: none  Cid: 01d4    Peb: 02e3d000  ParentCid: 0004
    DirBase: 9d53d080  ObjectTable: 93427d00  HandleCount:  53.
    Image: smss.exe

0: kd> .process /r /p 93248840
Implicit process is now 93248840
.cache forcedecodeuser done
Loading User Symbols
..
Unable to retrieve exception chain.  Stack unwind may not be completely reliable.
Unable to retrieve exception chain.  Stack unwind may not be completely reliable.
0: kd> uf ntdll!ZwcreateFile
ntdll!NtCreateFile:
76ff0500 b878010000      mov     eax,178h
76ff0505 e803000000      call    ntdll!NtCreateFile+0xd (76ff050d)
76ff050a c22c00          ret     2Ch

IDA�ķ�����
.text:6A2904F1                                              ; ---------------------------------------------------------------------------
.text:6A2904F2 8D A4 24 00 00 00 00 8D A4 24 00 00 00 00                    align 10h
.text:6A290500                                              ; Exported entry 294. NtCreateFile
.text:6A290500                                              ; Exported entry 1786. ZwCreateFile
.text:6A290500
.text:6A290500                                              ; =============== S U B R O U T I N E =======================================
.text:6A290500
.text:6A290500
.text:6A290500                                              ; __stdcall NtCreateFile(x, x, x, x, x, x, x, x, x, x, x)
.text:6A290500                                                              public _NtCreateFile@44
.text:6A290500                                              _NtCreateFile@44 proc near              ; CODE XREF: EtwpCreateFile(x,x,x,x,x,x)+C4��p
.text:6A290500                                                                                      ; RtlpFileIsWin32WithRCManifest(x)+8A��p ...
.text:6A290500 B8 78 01 00 00                                               mov     eax, 178h       ; NtCreateFile
.text:6A290505 E8 03 00 00 00                                               call    sub_6A29050D    ; Call Procedure
.text:6A290505
.text:6A29050A C2 2C 00                                                     retn    2Ch ; ','       ; Return Near from Procedure
.text:6A29050A
.text:6A29050A                                              _NtCreateFile@44 endp
.text:6A29050A
.text:6A29050D
.text:6A29050D                                              ; =============== S U B R O U T I N E =======================================
.text:6A29050D
.text:6A29050D
.text:6A29050D                                              sub_6A29050D    proc near               ; CODE XREF: NtCreateFile(x,x,x,x,x,x,x,x,x,x,x)+5��p
.text:6A29050D 8B D4                                                        mov     edx, esp
.text:6A29050F 0F 34                                                        sysenter                ; Fast Transition to System Call Entry Point
.text:6A290511 C3                                                           retn                    ; Return Near from Procedure
.text:6A290511
.text:6A290511                                              sub_6A29050D    endp
.text:6A290511
.text:6A290511                                              ; ---------------------------------------------------------------------------
*/
{
    PVOID ImageBase = 0;
    PVOID FunctionAddress;
    ANSI_STRING test;

    RtlInitAnsiString(&test, function_name);

    ImageBase = GetImageBase("ntdll.dll");
    if (ImageBase == 0) {
        return (ULONG)-1;
    }

    FunctionAddress = MiFindExportedRoutineByName(ImageBase, &test);
    if (FunctionAddress == 0) {
        return (ULONG)-1;
    }

#if defined(_AMD64_) || defined(_IA64_) //defined(_WIN64_) 
    //return SYSCALL_INDEX_64(FunctionAddress);
#else
    return SYSCALL_INDEX(FunctionAddress);
#endif 
}


#endif 


SIZE_T GetZwRoutineAddress(PCSTR RoutineName)
/*
���ܣ���ȡ�ں��е�Zwϵ�к����ĵ�ַ����Ҫ��û�е����ģ���֧��X86��AMD64��

ע�����
1.������������ڵ���������ִ�С�
2.������ʾ��������ĳ�ʼ�������õ���ȫ�ֱ�������ʱΪ��ʡ�¡�
3.�˺����д��Ľ����磺�����ͼ���ì�ܵģ�����ͬʱ���㡣
*/
{
    SIZE_T RoutineAddress = 0;
    ANSI_STRING ZwRoutineName = {0};

    RtlInitAnsiString(&ZwRoutineName, RoutineName);

#if defined(_AMD64_) || defined(_IA64_) 
    RoutineAddress = GetZwRoutineAddressByName(&ZwRoutineName);
#else
    RoutineAddress = (SIZE_T)(KeServiceDescriptorTable.ServiceTableBase[GetIndexOfSsdtFunction(RoutineName)]);
#endif 

    return RoutineAddress;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void SetZwQueryVirtualMemoryAddress(_In_ ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryAddress)
{
    InterlockedExchangePointer((PVOID volatile *)&ZwQueryVirtualMemoryFn, ZwQueryVirtualMemoryAddress);
}


void SetZwTerminateThreadAddress(_In_ ZwTerminateThread_pfn ZwTerminateThreadAddress)
{
    InterlockedExchangePointer((PVOID volatile *)&ZwTerminateThreadFn, ZwTerminateThreadAddress);
}


void SetRtlCreateUserThreadAddress(_In_ RtlCreateUserThreadFn RtlCreateUserThreadAddress)
{
    InterlockedExchangePointer((PVOID volatile *)&RtlCreateUserThread, RtlCreateUserThreadAddress);
}


void SetZwCreateThreadExAddress(_In_ RtlCreateUserThreadFn ZwCreateThreadExAddress)
{
    InterlockedExchangePointer((PVOID volatile *)&ZwCreateThreadEx, ZwCreateThreadExAddress);
}
