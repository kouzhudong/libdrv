#include "pch.h"
#include "Process.h"
#include "misc.h"


UNICODE_STRING gSystem = RTL_CONSTANT_STRING(L"System");


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL GetCommandLine(_In_ HANDLE PId, _Inout_ PUNICODE_STRING CommandLine)
/*
功能：获取进程的命令行。
办法：从PEB中取。

注意：
1.对于没有用户空间的进程，如：IDLE，system，registry，interrupts，memory compression等是获取不到的。
2.此函数用在进程回调中获取不到内容，线程回调的就不说了。
3.添加对类似进程回调等类似的情况，正常情况下没有试验。

PCL由调用者释放。
*/
{
    BOOL IsOk = FALSE;

    if (!PId) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "");
        return FALSE; //IDLE
    }

    if (PsGetProcessId(PsInitialSystemProcess) == PId) { //PsIsSystemThread
        return FALSE;                                    //system
    }

    PEPROCESS Process{};
    NTSTATUS Status = PsLookupProcessByProcessId(PId, &Process);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "pid:%u", HandleToULong(PId));
        return FALSE; //无效进程。
    }

    KAPC_STATE ApcState{};
    KeStackAttachProcess(Process, &ApcState);

    PPEB peb = PsGetProcessPeb(Process);
    if (peb) {
        __try {
            PRTL_USER_PROCESS_PARAMETERS ProcessParameters = peb->ProcessParameters;
            if (ProcessParameters) {
                CommandLine->MaximumLength = ProcessParameters->CommandLine.MaximumLength + sizeof(WCHAR);
                CommandLine->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, CommandLine->MaximumLength, TAG);
                if (nullptr == CommandLine->Buffer) {
                    Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
                } else {
                    RtlZeroMemory(CommandLine->Buffer, CommandLine->MaximumLength);

                    RtlCopyUnicodeString(CommandLine, &ProcessParameters->CommandLine);

                    IsOk = TRUE;
                }
            } else {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "pid:%u", HandleToULong(PId));
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Pid:%d", HandleToULong(Pid));//XP下有一部分会走这里。
        }
    } else {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "这个进程没有PEB, pid:%u", HandleToULong(PId));
    }

    KeUnstackDetachProcess(&ApcState);

    ObDereferenceObject(Process);

    return IsOk;
}


BOOL GetCurrentDirectory(_In_ HANDLE Pid, _Inout_ PUNICODE_STRING CurrentDirectory)
/*
功能：根据PEB获取CurrentDirectory。
起因：Procmon.exe和Sysmon.exe或procexp.exe都有获取CurrentDirectory的功能，此功能不大。
      但是以此扩展还能获取不少东西。
说明：这里演示的是根据PEB获取相关信息的思想。
      以此类推。
目的：兼容各个版本的Windows系统。

参考：https://blogs.msdn.microsoft.com/mithuns/2006/02/18/easiest-and-laziest-way-to-view-a-processs-command-line/

made by correy
made at 2017.02.15
homepage:http://correy.webs.com

注意：
1.用这个办法取ImagePathName，IDLE和system这两个应该获取不到。
2.此函数用在进程回调中获取不到内容，线程回调的就不说了。
3.添加对类似进程回调等类似的情况，正常情况下没有试验。
*/
{
    BOOL ret = FALSE;

    if (!Pid) {
        return FALSE; //IDLE
    }

    if (PsGetProcessId(PsInitialSystemProcess) == Pid) { //PsIsSystemThread
        return FALSE;                                    //system
    }

    PEPROCESS Process{};
    NTSTATUS Status = PsLookupProcessByProcessId(Pid, &Process);
    if (!NT_SUCCESS(Status)) {
        return FALSE; //无效进程。
    }

    KAPC_STATE ApcState{};
    KeStackAttachProcess(Process, &ApcState);

    PPEB peb = PsGetProcessPeb(Process); //注意：IDLE和system这两个应该获取不到。
    if (peb) {
        auto ProcessParameters = (PRTL_USER_PROCESS_PARAMETERS_WRK)peb->ProcessParameters;

        //KdPrint(("CurrentDirectory:%wZ\r\n", &ProcessParameters->CurrentDirectory.DosPath));

        CurrentDirectory->MaximumLength = ProcessParameters->CurrentDirectory.DosPath.MaximumLength;
        CurrentDirectory->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, CurrentDirectory->MaximumLength, TAG);
        if (nullptr == CurrentDirectory->Buffer) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
        } else {
            RtlZeroMemory(CurrentDirectory->Buffer, CurrentDirectory->MaximumLength);
            RtlCopyUnicodeString(CurrentDirectory, &ProcessParameters->CurrentDirectory.DosPath);
            ret = TRUE;
        }
    } else { //SYSTEM和MemCompression，IDLE等都没有PEB。
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "这个进程没有PEB, pid:%u", HandleToULong(Pid));
    }

    KeUnstackDetachProcess(&ApcState);

    ObDereferenceObject(Process);

    return ret;
}


NTSTATUS GetUserOfToken(_In_ PACCESS_TOKEN Token, _Out_ PUNICODE_STRING User)
/*

替代思路：
ZwQueryInformationToken(TokenUser) + RtlConvertSidToUnicodeString(SeConvertSidToStringSid导出但是未公开)

注意：成功后，需由调用方释放：FreeUnicodeString(User);
*/
{
    NTSTATUS Status = 0;
    PTOKEN_STATISTICS TokenInformation{};
    PSecurityUserData UserInformation{};

    if (!User) {
        return STATUS_INVALID_PARAMETER;
    }

    *User = {}; //UNICODE_NULL

    __try {
        Status = SeQueryInformationToken(Token, TokenStatistics, (PVOID *)&TokenInformation);
        if (!NT_SUCCESS(Status)) {

            __leave;
        }

        //还有一种情况也会发生如下情况,就是在Windows server 2008 X64上,具体的有待检查和添加.
        if (TokenInformation->AuthenticationId.HighPart == 0 &&
            TokenInformation->AuthenticationId.LowPart == 999) { //此数字即logon ID。
            /*
            https://msdn.microsoft.com/zh-cn/library/aa378290(v=vs.85).aspx

            If LogonID specifies the LocalSystem account (0x0:0x3e7),
            then this function returns zero for the logon session data retrieved in ppLogonSessionData.
            The reason is that the LocalSystem account does not get logged on in the typical logon manner.
            Rather, the LocalSystem account is active after the system starts.
            */

            //获取到了系统帐户,就是system,本地系统帐户.
            //打印的消息一般如下:
            //UserName :KOUDAQIANG-2008$
            //LogonServer :
            //LogonDomainName :WORKGROUP
            //SID :S-1-5-18

            UNICODE_STRING System = RTL_CONSTANT_STRING(L"NT AUTHORITY\\SYSTEM");

            User->MaximumLength = System.Length + sizeof(wchar_t);
            Status = AllocateUnicodeString(User);
            if (!NT_SUCCESS(Status)) {
                PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
                __leave;
            }

            //KdPrint(("UserName:system\n"));
            RtlCopyUnicodeString(User, &System);
            __leave;
        }

        Status = GetSecurityUserInfo(&TokenInformation->AuthenticationId, 0, &UserInformation);
        if (!NT_SUCCESS(Status)) {
            __leave;
        }

        User->MaximumLength = UserInformation->LogonDomainName.Length + 
                              UserInformation->UserName.Length + sizeof(wchar_t) + sizeof(wchar_t); //一个是斜杠，一个是NULL宽字符。
        Status = AllocateUnicodeString(User);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            __leave;
        }

        //User The user account in which the process is running, in DOMAIN\USER format.
        RtlCopyUnicodeString(User, &UserInformation->LogonDomainName);
        RtlAppendUnicodeToString(User, L"\\");
        RtlAppendUnicodeStringToString(User, &UserInformation->UserName);
    } __finally {
        if (!NT_SUCCESS(Status)) {
            FreeUnicodeString(User);
        }

        if (TokenInformation) {
            ExFreePool(TokenInformation);
        }

        if (UserInformation) {
            LsaFreeReturnBuffer(UserInformation);
        }
    }

    return Status;
}


NTSTATUS GetUserOfProcess(_In_ PEPROCESS Process, _Out_ PUNICODE_STRING User)
{
    NTSTATUS Status{};

    PACCESS_TOKEN PrimaryToken = PsReferencePrimaryToken(Process);
    if (PrimaryToken) {
        Status = GetUserOfToken(PrimaryToken, User);
        PsDereferencePrimaryToken(PrimaryToken);
    } else {
        Status = STATUS_UNSUCCESSFUL;
    }

    return Status;
}


NTSTATUS GetUserOfProcessId(_In_ HANDLE Pid, _Out_ PUNICODE_STRING User)
/*
打印当前操作的当前进程的用户名等.

功能:获取当前操作注册表的进程的用户.

SOURCE文件内容如下:
TARGETNAME=test

TARGETTYPE=DRIVER

TARGETLIBS=$(DDK_LIB_PATH)\ksecdd.lib

SOURCES=GetSecurityUserInfo.C

TARGETPATH=obj

made by correy
made at 2013.11.15
*/
{
    PEPROCESS Process{};
    NTSTATUS Status = PsLookupProcessByProcessId(Pid, &Process);
    if (NT_SUCCESS(Status)) {
        Status = GetUserOfProcess(Process, User);
        ObDereferenceObject(Process);
    } else {
    }

    return Status;
}


//#pragma alloc_text(PAGE, GetFullDosProcessImageFileName)
BOOL GetFullDosProcessImageFileName(_In_ PFLT_FILTER Filter, _In_opt_ PFLT_INSTANCE Instance, _In_ HANDLE Pid, _Inout_ PUNICODE_STRING FileName)
/*
对于IDLE，system，registry，interrupts，memory compression等是获取不到进程的路径的。
Registry进程的路径竟然能获取到：Registry，因为存在\Registry对象。

注意：
1.此函数不可用于OBh回调里，因为有ObOpenObjectByPointer。
2.也不可用于文件过滤回调中，因为有IoQueryFileDosDeviceName。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVOID us_ProcessImageFileName{}; //UNICODE_STRING
    ULONG ProcessInformationLength = 0;
    ULONG ReturnLength = 0;
    PEPROCESS EProcess{};
    HANDLE Handle{};
    PUNICODE_STRING p = nullptr;
    HANDLE File{};
    OBJECT_ATTRIBUTES ObjectAttributes{};
    IO_STATUS_BLOCK IoStatus{};
    PFILE_OBJECT FileObject{};
    POBJECT_NAME_INFORMATION FileNameInfo = nullptr;

    PAGED_CODE();

    if (nullptr == FileName || nullptr == FileName->Buffer || 0 == FileName->MaximumLength) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "");
        return FALSE;
    }

    if (!Pid) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "");
        return FALSE; //IDLE
    }

    if (PsGetProcessId(PsInitialSystemProcess) == Pid) {
        RtlCopyUnicodeString(FileName, &gSystem);
        return TRUE;
    }

    /*
    必须转换一下，不然是无效的句柄。
    句柄的类型转换为内核的。
    */
    Status = PsLookupProcessByProcessId(Pid, &EProcess);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return FALSE;
    }
    ObDereferenceObject(EProcess); //微软建议加上。
    Status = ObOpenObjectByPointer(EProcess, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsProcessType, KernelMode, &Handle);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return FALSE;
    }

    //获取需要的内存。
    Status = ZwQueryInformationProcess(Handle, ProcessImageFileName, us_ProcessImageFileName, ProcessInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ZwClose(Handle);
        return FALSE;
    }
    ReturnLength += sizeof(WCHAR);
    ProcessInformationLength = ReturnLength;
    us_ProcessImageFileName = ExAllocatePoolWithTag(PagedPool, ReturnLength, TAG);
    if (us_ProcessImageFileName == nullptr) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(Handle);
        return FALSE;
    }
    RtlZeroMemory(us_ProcessImageFileName, ReturnLength);

    Status = ZwQueryInformationProcess(Handle, ProcessImageFileName, us_ProcessImageFileName, ProcessInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ExFreePoolWithTag(us_ProcessImageFileName, TAG);
        ZwClose(Handle);
        return FALSE;
    }

    //KdPrint(("ProcessImageFileName:%wZ\n",ProcessFileName));//注意：中间有汉字是不会显示的。
    //形如：ProcessImageFileName:\Device\HarddiskVolume1\aa\Dbgvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvview.exe
    p = (PUNICODE_STRING)us_ProcessImageFileName;
    if (0 == p->Length) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x, pid:%u", Status, HandleToULong(Pid));
        ExFreePoolWithTag(us_ProcessImageFileName, TAG);
        ZwClose(Handle);
        return FALSE;
    }

    //获取DOS名.
    InitializeObjectAttributes(&ObjectAttributes, p, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    Status = FltCreateFile(Filter,
                           Instance,
                           &File,
                           FILE_READ_DATA | SYNCHRONIZE,
                           &ObjectAttributes,
                           &IoStatus,
                           nullptr,
                           FILE_ATTRIBUTE_NORMAL,
                           FILE_SHARE_READ,
                           FILE_OPEN,
                           FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT,
                           nullptr,
                           0,
                           IO_IGNORE_SHARE_ACCESS_CHECK);
    if (!NT_SUCCESS(Status)) {
        //STATUS_OBJECT_NAME_INVALID                0xC0000033L
        //STATUS_INVALID_DEVICE_OBJECT_PARAMETER    0xC0000369L 启动时会返回这个值，设备已经挂载了。
        //STATUS_OBJECT_PATH_SYNTAX_BAD             0xC000003BL
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:0x%X, pid:%u, FileName:%wZ", Status, HandleToULong(Pid), p);
        ExFreePoolWithTag(us_ProcessImageFileName, TAG);
        ZwClose(Handle);
        return FALSE;
    }

    Status = ObReferenceObjectByHandle(File, FILE_READ_ACCESS, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, nullptr);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ExFreePoolWithTag(us_ProcessImageFileName, TAG);
        ZwClose(Handle);
        ZwClose(File);
        return FALSE;
    }

    //此函数不支持XP，但支持2003.
    //if (KeAreAllApcsDisabled())
    //{
    //    ExFreePoolWithTag(ProcessFileName, TAG);
    //    ZwClose(KernelHandle);
    //    ZwClose(File);
    //    return FALSE;
    //}

    Status = IoQueryFileDosDeviceName(FileObject, &FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ExFreePoolWithTag(us_ProcessImageFileName, TAG);
        ObDereferenceObject(FileObject);
        ZwClose(Handle);
        ZwClose(File);
        return FALSE;
    }

    if (FileNameInfo->Name.Length >= MAX_PATH * sizeof(WCHAR)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Length:%u, FileName:%wZ", FileNameInfo->Name.Length, &FileNameInfo->Name);
        ExFreePool(FileNameInfo);
        ObDereferenceObject(FileObject);
        ZwClose(File);
        ExFreePoolWithTag(us_ProcessImageFileName, TAG);
        ZwClose(Handle);
        return FALSE;
    }

    //KdPrint(("dos name:%wZ.\r\n", &FileNameInfo->Name));
    RtlCopyUnicodeString(FileName, &FileNameInfo->Name);

    ExFreePool(FileNameInfo);
    ObDereferenceObject(FileObject);
    ZwClose(File);
    ExFreePoolWithTag(us_ProcessImageFileName, TAG);
    ZwClose(Handle);
    return TRUE;
}


//#pragma alloc_text(PAGE, GetFullNtProcessImageFileName)
BOOL GetFullNtProcessImageFileName(_In_ HANDLE Pid, _Inout_ PUNICODE_STRING * ProcessFileName)
/*
功能：获取进程完全的NT名。

对于IDLE，system，registry，interrupts，memory compression等是获取不到进程的路径的。
Registry进程的路径竟然能获取到：Registry，因为存在\Registry对象。

注意：
1.此函数不可用于OBh回调里。
2.ProcessFileName的内存由调用者释放。
*/
{
    PAGED_CODE();

    if (nullptr == ProcessFileName) {
        return FALSE;
    }

    *ProcessFileName = nullptr;

    if (!Pid) {
        return FALSE; //IDLE
    }

    if (PsGetProcessId(PsInitialSystemProcess) == Pid) {
        return FALSE;
    }

    /*
    必须转换一下，不然是无效的句柄。
    句柄的类型转换为内核的。
    */
    PEPROCESS Process{};
    NTSTATUS Status = PsLookupProcessByProcessId(Pid, &Process);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return FALSE;
    }
    ObDereferenceObject(Process); //微软建议加上。
    HANDLE Handle{};
    Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsProcessType, KernelMode, &Handle);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return FALSE;
    }

    //获取需要的内存。
    ULONG ProcessInformationLength = 0;
    ULONG ReturnLength = 0;
    Status = ZwQueryInformationProcess(Handle, ProcessImageFileName, *ProcessFileName, ProcessInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ZwClose(Handle);
        return FALSE;
    }
    ProcessInformationLength = ReturnLength;
    *ProcessFileName = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, ReturnLength, TAG);
    if (*ProcessFileName == nullptr) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(Handle);
        return FALSE;
    }
    RtlZeroMemory(*ProcessFileName, ReturnLength);

    //真正的操作。
    BOOL ret = TRUE;
    Status = ZwQueryInformationProcess(Handle, ProcessImageFileName, *ProcessFileName, ProcessInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ExFreePoolWithTag(*ProcessFileName, TAG);
        ret = FALSE;
    }

    //KdPrint(("ProcessImageFileName:%wZ\n",ProcessFileName));//注意：中间有汉字是不会显示的。
    //形如：ProcessImageFileName:\Device\HarddiskVolume1\aa\Dbgvvvvvvvvvvvvvvvvview.exe

    ZwClose(Handle);
    return ret;
}


BOOL GetProcessImageName(_In_ HANDLE pid, _Inout_ PUNICODE_STRING ImagePathName)
/*
功能：获取进程的全路径。

注意：
1.适用于ObRegisterCallbacks中。
2.获取的是NT路径。
3.可用于文件过滤的回调中。
*/
{
    BOOL ret = FALSE;

    PAGED_CODE();

    if (!pid) {
        return FALSE; //IDLE
    }

    if (PsGetProcessId(PsInitialSystemProcess) == pid) { //PsIsSystemThread
        ImagePathName->MaximumLength = gSystem.MaximumLength;
        ImagePathName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, ImagePathName->MaximumLength, TAG);
        if (nullptr == ImagePathName->Buffer) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
            return FALSE;
        } else {
            RtlZeroMemory(ImagePathName->Buffer, ImagePathName->MaximumLength);
            RtlCopyUnicodeString(ImagePathName, &gSystem);
            return TRUE; //system
        }
    }

    PEPROCESS eprocess{};
    NTSTATUS Status = PsLookupProcessByProcessId(pid, &eprocess);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return FALSE; //无效进程。
    }

    KAPC_STATE ApcState{};
    KeStackAttachProcess(eprocess, &ApcState);

    PUNICODE_STRING temp = nullptr;
    Status = SeLocateProcessImageName(eprocess, &temp);
    if (NT_SUCCESS(Status)) {
        ImagePathName->MaximumLength = temp->MaximumLength;
        ImagePathName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, ImagePathName->MaximumLength, TAG);
        if (nullptr == ImagePathName->Buffer) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
        } else {
            RtlZeroMemory(ImagePathName->Buffer, ImagePathName->MaximumLength);
            RtlCopyUnicodeString(ImagePathName, temp);
            ret = TRUE;
        }

        ExFreePool(temp);
    }

    if (!ret) {
        if (ImagePathName->Buffer) {
            ExFreePoolWithTag(ImagePathName->Buffer, TAG);

            //这个很重要。
            ImagePathName->Buffer = nullptr;
            ImagePathName->MaximumLength = 0;
            ImagePathName->Length = 0;
        }
    }

    KeUnstackDetachProcess(&ApcState);

    ObDereferenceObject(eprocess);

    return ret;
}


NTSTATUS GetLogonId(_Inout_ PLUID LogonId)
/*
打印当前操作的当前进程的用户名等.
*/
{
    PACCESS_TOKEN pat = PsReferencePrimaryToken(PsGetCurrentProcess());

    PTOKEN_STATISTICS pts{};
    NTSTATUS Status = SeQueryInformationToken(pat, TokenStatistics, (PVOID *)&pts);
    if (!NT_SUCCESS(Status)) {
        PsDereferencePrimaryToken(pat);
        return Status;
    }

    LogonId->HighPart = pts->AuthenticationId.HighPart;
    LogonId->LowPart = pts->AuthenticationId.LowPart;

    PsDereferencePrimaryToken(pat);

    return Status;
}


DWORD GetProcessIntegrityLevelFromDword(_In_ DWORD Integrity)
{
    if (/*Integrity >= SECURITY_MANDATORY_UNTRUSTED_RID && */ Integrity < SECURITY_MANDATORY_LOW_RID) {
        return SECURITY_MANDATORY_UNTRUSTED_RID;
    } else if (Integrity >= SECURITY_MANDATORY_LOW_RID && Integrity < SECURITY_MANDATORY_MEDIUM_RID) {
        return SECURITY_MANDATORY_LOW_RID; //Process Explorer显示为AppContainer。
    } else if (Integrity >= SECURITY_MANDATORY_MEDIUM_RID && Integrity < SECURITY_MANDATORY_HIGH_RID /*SECURITY_MANDATORY_MEDIUM_PLUS_RID*/) {
        return SECURITY_MANDATORY_MEDIUM_RID;
    }
    //else if (Integrity >= SECURITY_MANDATORY_MEDIUM_PLUS_RID && Integrity < SECURITY_MANDATORY_HIGH_RID)
    //{
    //    return L"Medium Plus";
    //}
    else if (Integrity >= SECURITY_MANDATORY_HIGH_RID && Integrity < SECURITY_MANDATORY_SYSTEM_RID) {
        return SECURITY_MANDATORY_HIGH_RID;
    } else if (Integrity >= SECURITY_MANDATORY_SYSTEM_RID && Integrity < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
        return SECURITY_MANDATORY_SYSTEM_RID;
    } else {
        KdBreakPoint();
    }

    return static_cast<DWORD>(-1);
}


DWORD GetProcessIntegrityLevelFromString(_In_ PWCHAR Integrity)
{
    if (_wcsicmp(Integrity, L"Untrusted") == 0) {
        return SECURITY_MANDATORY_UNTRUSTED_RID;
    } else if (_wcsicmp(Integrity, L"Low") == 0) {
        return SECURITY_MANDATORY_LOW_RID; //Process Explorer显示为AppContainer。
    } else if (_wcsicmp(Integrity, L"Medium") == 0) {
        return SECURITY_MANDATORY_MEDIUM_RID;
    }
    //else if (Integrity >= SECURITY_MANDATORY_MEDIUM_PLUS_RID && Integrity < SECURITY_MANDATORY_HIGH_RID)
    //{
    //    return L"Medium Plus";
    //}
    else if (_wcsicmp(Integrity, L"High") == 0) {
        return SECURITY_MANDATORY_HIGH_RID;
    } else if (_wcsicmp(Integrity, L"System") == 0) {
        return SECURITY_MANDATORY_SYSTEM_RID;
    } else {
        KdBreakPoint();
    }

    return static_cast<DWORD>(-1);
}


DWORD GetProcessIntegrityLevel(_In_ HANDLE UniqueProcess)
{
    CLIENT_ID ClientId{};
    OBJECT_ATTRIBUTES ob{};
    HANDLE ProcessHandle{};
    DWORD Integrity = 0;

    if (!UniqueProcess) { //IDLE进程放过。
        return 0;
    }

    ClientId.UniqueProcess = UniqueProcess;
    InitializeObjectAttributes(&ob, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    NTSTATUS Status = ZwOpenProcess(&ProcessHandle, GENERIC_ALL, &ob, &ClientId);
    ASSERT(NT_SUCCESS(Status));

    HANDLE TokenHandle{};
    Status = ZwOpenProcessTokenEx(ProcessHandle, TOKEN_READ, OBJ_KERNEL_HANDLE, &TokenHandle);
    ASSERT(NT_SUCCESS(Status));

    ULONG ReturnLength{};
    Status = ZwQueryInformationToken(TokenHandle, TokenIntegrityLevel, nullptr, 0, &ReturnLength);
    ASSERT(!NT_SUCCESS(Status));
    ASSERT(STATUS_BUFFER_TOO_SMALL == Status);
    ASSERT(ReturnLength);

    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)ExAllocatePoolWithTag(PagedPool, ReturnLength, TAG);
    if (nullptr == pTIL) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
    } else {
        RtlZeroMemory(pTIL, ReturnLength);
        Status = ZwQueryInformationToken(TokenHandle, TokenIntegrityLevel, pTIL, ReturnLength, &ReturnLength);
        ASSERT(NT_SUCCESS(Status));

        DWORD SubAuthority = (*RtlSubAuthorityCountSid(pTIL->Label.Sid) - 1);
        Integrity = *RtlSubAuthoritySid(pTIL->Label.Sid, SubAuthority);

        ExFreePoolWithTag(pTIL, TAG);
    }

    Status = ZwClose(TokenHandle);
    Status = ZwClose(ProcessHandle);
    return Integrity;
}


void ShowProcessIntegrityLevel(HANDLE UniqueProcess)
/*
功能：ShowProcessIntegrityLevel。

参考：https://msdn.microsoft.com/en-us/library/bb625966.aspx

注意：这个属性在Vista及以后的版本上才有。

made by correy
made at 2017.04.05
homepage:http://correy.webs.com
*/
{
    DWORD Integrity = GetProcessIntegrityLevel(UniqueProcess);

    if (/*Integrity >= SECURITY_MANDATORY_UNTRUSTED_RID && */ Integrity < SECURITY_MANDATORY_LOW_RID) {
        KdPrint(("PID:%u, Integrity:Untrusted.\r\n", HandleToULong(UniqueProcess)));
    } else if (Integrity >= SECURITY_MANDATORY_LOW_RID && Integrity < SECURITY_MANDATORY_MEDIUM_RID) {
        KdPrint(("PID:%u, Integrity:Low.\r\n", HandleToULong(UniqueProcess))); //Process Explorer显示为AppContainer。
    } else if (Integrity >= SECURITY_MANDATORY_MEDIUM_RID && Integrity < SECURITY_MANDATORY_MEDIUM_PLUS_RID) {
        KdPrint(("PID:%u, Integrity:Medium.\r\n", HandleToULong(UniqueProcess)));
    } else if (Integrity >= SECURITY_MANDATORY_MEDIUM_PLUS_RID && Integrity < SECURITY_MANDATORY_HIGH_RID) {
        KdPrint(("PID:%u, Integrity:Medium Plus.\r\n", HandleToULong(UniqueProcess)));
    } else if (Integrity >= SECURITY_MANDATORY_HIGH_RID && Integrity < SECURITY_MANDATORY_SYSTEM_RID) {
        KdPrint(("PID:%u, Integrity:High.\r\n", HandleToULong(UniqueProcess)));
    } else if (Integrity >= SECURITY_MANDATORY_SYSTEM_RID && Integrity < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) {
        KdPrint(("PID:%u, Integrity:System.\r\n", HandleToULong(UniqueProcess)));
    } else {
        KdPrint(("PID:%u, Integrity:Invalid.\r\n", HandleToULong(UniqueProcess)));
    }
}


DWORD GetSessionId(_In_ PEPROCESS Process)
/*
功能：获取进程的会话ID。

另一个实现办法是用高版本的PsGetProcessSessionId。
*/
{
    DWORD SessionId = 0;

    PACCESS_TOKEN AccessToken = PsReferencePrimaryToken(Process); //PsGetCurrentProcess()

    /*
    The buffer receives a DWORD value that indicates the Terminal Services session identifier associated with the token.
    If the token is associated with the Terminal Server console session, the session identifier is zero.
    A nonzero session identifier indicates a Terminal Services client session.
    In a non-Terminal Services environment, the session identifier is zero.
    */
    PVOID TokenInformation = nullptr;
    NTSTATUS Status = SeQueryInformationToken(AccessToken, TokenSessionId, &TokenInformation);
    if (NT_SUCCESS(Status)) {
        //SessionId = *(DWORD *)TokenInformation;//TokenInformation有肯能为0.

#pragma warning(push)
#pragma warning(disable : 4311)
#pragma warning(disable : 4302)
        SessionId = (DWORD)TokenInformation;
#pragma warning(pop)

        //KdPrint(("TokenSessionId:%d.\r\n", SessionId));
    } else {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
    }

    PsDereferencePrimaryToken(AccessToken);

    return SessionId;
}


NTSTATUS GetProcessImageFileName(_In_ HANDLE Pid, _Inout_ PUNICODE_STRING ProcessName)
/*
功能：获取进程名，只是进程名，不是全路径，常用于临时性的测试。
*/
{
    PEPROCESS Process{};
    HANDLE KernelHandle{};
    NTSTATUS Status{};
    PVOID ProcessInformation{}; //UNICODE_STRING

    __try {
        /*
        必须转换一下，不然是无效的句柄。
        */
        Status = PsLookupProcessByProcessId(Pid, &Process);
        if (!NT_SUCCESS(Status)) {
            //KdPrint(("PsLookupProcessByProcessId fail with 0x%x in line %d\n",Status, __LINE__));
            __leave;
        }

        Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsProcessType, KernelMode, &KernelHandle);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //获取需要的内存。
        ULONG ProcessInformationLength = 0;
        ULONG ReturnLength = 0;
        Status = ZwQueryInformationProcess(KernelHandle, ProcessImageFileName, ProcessInformation, ProcessInformationLength, &ReturnLength);
        if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            __leave;
        }
        ProcessInformationLength = ReturnLength;
        ProcessInformation = ExAllocatePoolWithTag(PagedPool, ReturnLength, TAG);
        if (ProcessInformation == nullptr) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        RtlZeroMemory(ProcessInformation, ReturnLength);

        Status = ZwQueryInformationProcess(KernelHandle, ProcessImageFileName, ProcessInformation, ProcessInformationLength, &ReturnLength);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //KdPrint(("ProcessImageFileName:%wZ\n",ProcessFileName));//注意：中间有汉字是不会显示的。
        //形如：ProcessImageFileName:\Device\HarddiskVolume1\aa\Dbgvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvview.exe
        auto p = (UNICODE_STRING *)ProcessInformation;

        if (p->Length == 0) {
            //KdPrint(("p->Length == 0 in line %d\n", __LINE__));
            __leave;
        }

        //从末尾开始搜索斜杠。
        USHORT i = 0;
        for (i = p->Length / 2 - 1;; i--) {
            if (p->Buffer[i] == L'\\') {
                break;
            }
        }

        i++; //跳过斜杠。

        //构造文件名结构，复制用的。
        UNICODE_STRING temp = {0};
        temp.Length = p->Length - i * 2;
        temp.MaximumLength = p->MaximumLength - i * 2;
        temp.Buffer = &p->Buffer[i];

        ProcessName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, MAX_PATH, TAG); //这个内存由调用者释放。
        if (ProcessName->Buffer == nullptr) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }
        RtlZeroMemory(ProcessName->Buffer, MAX_PATH);
        RtlInitEmptyUnicodeString(ProcessName, ProcessName->Buffer, MAX_PATH);

        RtlCopyUnicodeString(ProcessName, &temp);
        //KdPrint(("ProcessImageFileName:%wZ\n",ProcessName));
    } __finally {
        if (ProcessInformation) {
            ExFreePoolWithTag(ProcessInformation, TAG);
        }

        if (KernelHandle) {
            ZwClose(KernelHandle);
        }

        if (Process) {
            ObDereferenceObject(Process);
        }
    }

    return Status;
}


NTSTATUS GetPidFromProcessName(_In_ PWSTR ProcessName, _Inout_ PHANDLE UniqueProcessId)
/*
功能：根据进程名获取PID。
作用：1.测试常用。
      2.对于根据进程的名操作，如：根据进程名结束进程等。
说明：1.如果指定的进程名有多个只返回一个。
      2.如果指定的进程名不存在，返回STATUS_INVALID_HANDLE;//STATUS_UNSUCCESSFUL。
话外题：这个目的还有别的好办法吗？
        1.ZwOpenProcess好像是最直接的函数，但是总是失败。
        2.暴力枚举进程还不如本办法的ZwQuerySystemInformation + SystemProcessInformation，别的枚举进程方法类似。

made by correy
made at 2015.07.08.
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SYSTEM_PROCESS_INFORMATION buffer = {0};
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = &buffer;
    ULONG SystemInformationLength = 0;
    ULONG ReturnLength = 0;
    UNICODE_STRING temp = {0};

    //参数检查就不做了。

    *UniqueProcessId = ULongToHandle((const unsigned long)STATUS_INVALID_HANDLE); //默认设置。有可能找不到，也就是不存在。

    RtlInitUnicodeString(&temp, ProcessName);

    //获取需要的内存。
    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return Status;
    }
    ReturnLength *= 2; //第一次需求0x9700，第二次需求0x9750,所以乘以2.
    SystemInformationLength = ReturnLength;
    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(PagedPool, ReturnLength, TAG);
    if (ProcessInfo == nullptr) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(ProcessInfo, ReturnLength);

    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(ProcessInfo, TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (auto it = ProcessInfo; /* it->NextEntryOffset != 0 */; /*it++*/) //注释的都是有问题的，如少显示一个等。
    {
        UNICODE_STRING FileName = {0};
        if (NT_SUCCESS(GetProcessImageFileName(it->UniqueProcessId, &FileName))) {
            if (RtlCompareUnicodeString(&FileName, &temp, TRUE) == 0) {
                RtlFreeUnicodeString(&FileName);
                *UniqueProcessId = it->UniqueProcessId;
                break;
            }

            RtlFreeUnicodeString(&FileName);
        }

        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "PID:%p\tNumberOfThreads:%u\tHandleCount:%u", it->UniqueProcessId, it->NumberOfThreads, it->HandleCount);

        /*
        The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member.
        For the last item in the array, NextEntryOffset is 0.
        摘自：http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx。
        说明：NextEntryOffset的值是不固定的，更不是SYSTEM_PROCESS_INFORMATION结构的大小。所以不能加一个结构的大小来遍历。
        */

        if (it->NextEntryOffset == 0) {
            break;
        }

        it = (PSYSTEM_PROCESS_INFORMATION)((char *)it + it->NextEntryOffset);
    }

    if (*UniqueProcessId == ULongToHandle((const unsigned long)STATUS_INVALID_HANDLE)) { //进程名不存在，没有找到。
        Status = STATUS_INVALID_HANDLE;                                                  //STATUS_UNSUCCESSFUL
    }

    ExFreePoolWithTag(ProcessInfo, TAG);

    return Status; //STATUS_SUCCESS
}


NTSTATUS EnumProcess(_In_ HandleProcess CallBack, _In_opt_ PVOID Context)
/*
功能：通用的处理所有进程的函数。

回调函数的参数最好是PSYSTEM_PROCESS_INFORMATION，因为这样包含的信息多，剩的再去获取了。
但是这样有缺点，一是带的信息多，二是定义冲突等。
所以回调函数的参数还是HANDLE UniqueProcessId吧！
这样，你想要的信息，你再获取。

回调函数的第二个参数是上下文，用于输出和输入信息，具体的类型自己定义，也可以没有。

诚如代码所示：
1.回调函数注册一次，会被调用多次。
2.可以考虑根据回调函数的返回值，判断是否继续/退出。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SYSTEM_PROCESS_INFORMATION temp = {0};
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = &temp;
    ULONG SystemInformationLength = 0;
    ULONG ReturnLength = 0;

    //获取需要的内存。
    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return Status;
    }
    ReturnLength *= 2; //第一次需求0x9700，第二次需求0x9750,所以乘以2.
    SystemInformationLength = ReturnLength;
    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLength, TAG);
    if (ProcessInfo == nullptr) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return Status;
    }
    RtlZeroMemory(ProcessInfo, ReturnLength);

    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(ProcessInfo, TAG);
        return Status;
    }

    for (auto it = ProcessInfo; /* it->NextEntryOffset != 0 */; /*it++*/) //注释的都是有问题的，如少显示一个等。
    {
        if (CallBack) {
            Status = CallBack(it->UniqueProcessId, Context);
            if (NT_SUCCESS(Status)) {
                break;
            }
        }

        /*
        The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member.
        For the last item in the array, NextEntryOffset is 0.
        摘自：http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx。
        说明：NextEntryOffset的值是不固定的，更不是SYSTEM_PROCESS_INFORMATION结构的大小。所以不能加一个结构的大小来遍历。
        */

        if (it->NextEntryOffset == 0) {
            break;
        }

        it = (PSYSTEM_PROCESS_INFORMATION)((char *)it + it->NextEntryOffset);
    }

    ExFreePoolWithTag(ProcessInfo, TAG);

    return Status; //STATUS_SUCCESS
}


HANDLE GetParentsPID(_In_ HANDLE UniqueProcessId)
/*
功能：获取一个进程的父进程。
*/
{
    HANDLE ParentsPID{};

    /*
    必须转换一下，不然是无效的句柄。
    大概是句柄的类型转换为内核的。
    */
    PEPROCESS Process{};
    NTSTATUS Status = PsLookupProcessByProcessId(UniqueProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return ParentsPID;
    }

    ObDereferenceObject(Process); //微软建议加上。

    HANDLE KernelHandle{};
    Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsProcessType, KernelMode, &KernelHandle); //注意要关闭句柄。
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return ParentsPID;
    }

    PROCESS_BASIC_INFORMATION ProcessBasicInfo = {0};
    ULONG ReturnLength = 0;
    Status = ZwQueryInformationProcess(KernelHandle, ProcessBasicInformation, &ProcessBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ZwClose(KernelHandle);
        return ParentsPID;
    }

#ifdef _X86_
    ParentsPID = ULongToHandle(PtrToUlong(ProcessBasicInfo.InheritedFromUniqueProcessId));
#else
    ParentsPID = (HANDLE)ProcessBasicInfo.InheritedFromUniqueProcessId;
#endif

    ZwClose(KernelHandle);
    return ParentsPID;
}


NTSTATUS GetAllChildProcess(_In_ HANDLE UniqueProcessId)
/*
功能：获取一个进程的所有的子进程(甚至是孙进程，子子孙孙无穷尽的进程，但不是JOB那种)。

做法：遍历。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    SYSTEM_PROCESS_INFORMATION buffer = {0};
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = &buffer;
    PSYSTEM_PROCESS_INFORMATION iter{};
    ULONG SystemInformationLength = 0;
    ULONG ReturnLength = 0;

    //参数检查就不做了。

    //获取需要的内存。
    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return Status;
    }
    ReturnLength *= 2; //第一次需求0x9700，第二次需求0x9750,所以乘以2.
    SystemInformationLength = ReturnLength;
    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLength, TAG);
    if (ProcessInfo == nullptr) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(ProcessInfo, ReturnLength);

    Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInfo, SystemInformationLength, &ReturnLength);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ExFreePoolWithTag(ProcessInfo, TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (iter = ProcessInfo; /* iter->NextEntryOffset != 0 */; /*iter++*/) //注释的都是有问题的，如少显示一个等。
    {
        HANDLE ParentsPID = GetParentsPID(iter->UniqueProcessId);
        if (UniqueProcessId == ParentsPID) {
#pragma warning(push)
#pragma warning(disable : 6271)
            DbgPrint("%u的子进程：%u.\n", HandleToULong(UniqueProcessId), HandleToULong(iter->UniqueProcessId));
#pragma warning(pop)            

            //GetAllChildProcess(iter->UniqueProcessId);//可以考虑递归。注意断链。
        }

        //KdPrint(("PID:%d\tNumberOfThreads:%d\tHandleCount:%d\n",
        //         iter->UniqueProcessId, iter->NumberOfThreads, iter->HandleCount));

        /*
        The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member.
        For the last item in the array, NextEntryOffset is 0.
        摘自：http://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx。
        说明：NextEntryOffset的值是不固定的，更不是SYSTEM_PROCESS_INFORMATION结构的大小。所以不能加一个结构的大小来遍历。
        */

        if (iter->NextEntryOffset == 0) {
            break;
        }

        iter = (PSYSTEM_PROCESS_INFORMATION)((char *)iter + iter->NextEntryOffset);
    }

    ExFreePoolWithTag(ProcessInfo, TAG);

    return Status; //STATUS_SUCCESS
}


NTSTATUS GetJobNameOfProcess(_In_ HANDLE Pid)
/*
功能：获取进程的JOB的名字。
原理或者办法是：PsGetProcessJob + ObQueryNameString。
其实可以写一个函数，函数的名字为：ZwGetProcessJobName。

XP中到处的包含JOB的函数      | 应用层的函数及自己的注释。
-------------------------------------------------------------------------
PsGetJobLock                 | JOB的锁？
PsGetJobSessionId            | 获取JOB的会话ID。有进程会话ID了还要这个？
PsGetJobUIRestrictionsClass  | 不解。UIRestrictionsClass？
PsGetProcessJob              | 本文有用法示例。
PsJobType                    | 一个变量：JOB内核对象
PsSetJobUIRestrictionsClass  | 不解。UIRestrictionsClass？
ZwAssignProcessToJobObject   | AssignProcessToJobObject
ZwCreateJobObject            | CreateJobObject
ZwIsProcessInJob             | IsProcessInJob
ZwOpenJobObject              | OpenJobObject
ZwQueryInformationJobObject  | QueryInformationJobObject
ZwSetInformationJobObject    | SetInformationJobObject
ZwTerminateJobObject         | TerminateJobObject
没有找到对应的函数           | UserHandleGrantAccess

made by correy
made at 2015.07.13.
*/
{
    PEPROCESS EProcess{};
    NTSTATUS Status = PsLookupProcessByProcessId(Pid, &EProcess);
    if (NT_SUCCESS(Status)) {
        PEJOB job = PsGetProcessJob(EProcess);
        if (nullptr != job) {
            ULONG len = 0;
            Status = ObQueryNameString(job, nullptr, len, &len);
            ASSERT(!NT_SUCCESS(Status));
            if (0 == len) {
                PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            } else {
                PUNICODE_STRING JobName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, len, TAG);
                if (nullptr != JobName) {
                    Status = ObQueryNameString(job, (POBJECT_NAME_INFORMATION)JobName, len, &len);
                    if (!NT_SUCCESS(Status)) {
                        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
                    } else {
                        KdPrint(("JobName:%wZ\n", JobName)); //形如：\BaseNamedObjects\XXXXX
                    }

                    ExFreePoolWithTag(JobName, TAG);
                }
            }
        }

        ObDereferenceObject(EProcess); //微软建议加上。
    } else {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
    }

    return Status;
}


NTSTATUS ZwAllocateHeap()
/*
文件名：RtlCreateHeap.c
其实最主要的还是RtlCreateHeap的说明，注意这个可以有回调函数。
RtlAllocateHeap这个函数也不能在指定的地址上申请内存。

运行结果如下：
HeapHandle == 00180000!
p == 00180688!

这些内存在哪个进程呢？系统进程（SYSTEM）
函数没有指明，但是函数的说明指明了。

made by correy
made at 2014.09.04
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PVOID HeapHandle = RtlCreateHeap(0, nullptr, 0, 0, nullptr, nullptr);
    if (HeapHandle == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KdPrint(("HeapHandle == %p!\n", HeapHandle));

    SIZE_T Size = 9;
    PVOID p = RtlAllocateHeap(HeapHandle, HEAP_ZERO_MEMORY, Size);
    if (p == nullptr) {
        HeapHandle = RtlDestroyHeap(HeapHandle);
        if (HeapHandle != nullptr) {
            KdPrint(("RtlDestroyHeap fails!\n"));
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KdPrint(("p == %p!\n", p));

    __try {
        ULONG Alignment = 1;
        ProbeForWrite(p, Size, Alignment);
        *(char *)p = 9;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "ExceptionCode:%#X", GetExceptionCode());
    }

    BOOLEAN B = (BOOLEAN)RtlFreeHeap(HeapHandle, HEAP_NO_SERIALIZE, p);
    if (B == FALSE) {
        KdPrint(("RtlFreeHeap fails!\n"));
    }

    HeapHandle = RtlDestroyHeap(HeapHandle);
    if (HeapHandle != nullptr) {
        KdPrint(("RtlDestroyHeap fails!\n"));
    }

    return Status;
}


NTSTATUS IsSecureProcess(_In_ HANDLE ProcessHandle, _Out_ BOOLEAN * SecureProcess)
/*
Isolated User Mode (IUM) Processes

Windows 10 introduced a new security feature named Virtual Secure Mode (VSM).
VSM leverages the Hyper-V Hypervisor and Second Level Address Translation (SLAT) to create a set of modes called Virtual Trust Levels (VTLs).
This new software architecture creates a security boundary to prevent processes running in one VTL from accessing the memory of another VTL.
The benefit of this isolation includes additional mitigation from kernel exploits while protecting assets such as password hashes and Kerberos keys.

Diagram 1 depicts the traditional model of Kernel mode and User mode code running in CPU ring 0 and ring 3, respectively.
In this new model, the code running in the traditional model executes in VTL0 and it cannot access the higher privileged VTL1,
where the Secure Kernel and Isolated User Mode (IUM) execute code.
The VTLs are hierarchal meaning any code running in VTL1 is more privileged than code running in VTL0.

The VTL isolation is created by the Hyper-V Hypervisor which assigns memory at boot time using Second Level Address Translation (SLAT).
It continues this dynamically as the system runs, protecting memory the Secure Kernel specifies needing protection from VTL0 because it will be used to contain secrets.
As separate blocks of memory are allocated for the two VTLs,
a secure runtime environment is created for VTL1 by assigning exclusive memory blocks to VTL1 and VTL0 with the appropriate access permissions.

Trustlets
Trustlets (also known as trusted processes, secure processes, or IUM processes) are programs running as IUM processes in VSM.
They complete system calls by marshalling them over to the Windows kernel running in VTL0 ring 0.
VSM creates a small execution environment that includes the small Secure Kernel executing in VTL1 (isolated from the kernel and drivers running in VTL0).
The clear security benefit is isolation of trustlet user mode pages in VTL1 from drivers running in the VTL0 kernel.
Even if kernel mode of VTL0 is compromised by malware, it will not have access to the IUM process pages.

With VSM enabled, the Local Security Authority (LSASS) environment runs as a trustlet.
LSASS manages the local system policy, user authentication,
and auditing while handling sensitive security data such as password hashes and Kerberos keys.
To leverage the security benefits of VSM,
a trustlet named LSAISO.exe (LSA Isolated) runs in VTL1 and
communicates with LSASS.exe running in VTL0 through an RPC channel.
The LSAISO secrets are encrypted before sending them over to LSASS running in VSM Normal Mode and
the pages of LSAISO are protected from malicious code running in VTL0.

solated User Mode (IUM) Implications
It is not possible to attach to an IUM process, inhibiting the ability to debug VTL1 code.
This includes post mortem debugging of memory dumps and attaching the Debugging Tools for live debugging.
It also includes attempts by privileged accounts or kernel drivers to load a DLL into an IUM process,
to inject a thread, or deliver a user-mode APC. Such attempts may result in destabilization of the entire system.
Windows APIs that would compromise the security of a Trustlet may fail in unexpected ways.
For example, loading a DLL into a Trustlet will make it available in VTL0 but not VTL1.
QueueUserApc may silently fail if the target thread is in a Trustlet.
Other APIs, such as CreateRemoteThread, VirtualAllocEx,
and Read/WriteProcessMemory will also not work as expected when used against Trustlets.

Use the sample code below to prevent calling any functions which attempt to attach or inject code into an IUM process.
This includes kernel drivers that queue APCs for execution of code in a trustlet.

If the return Status of IsSecureProcess is success, examine the SecureProcess _Out_ parameter to determine if the process is an IUM process.
IUM processes are marked by the system to be “Secure Processes”.
A Boolean result of TRUE means the target process is of type IUM.

The WDK for Windows 10, “Windows Driver Kit - Windows 10.0.15063.0”,
contains the required definition of the PROCESS_EXTENDED_BASIC_INFORMATION structure.
The updated version of the structure is defined in ntddk.h with the new IsSecureProcess field.

https://docs.microsoft.com/zh-cn/windows/win32/procthread/isolated-user-mode--ium--processes
*/
{
    NTSTATUS Status{};
    PROCESS_EXTENDED_BASIC_INFORMATION extendedInfo = {0}; // definition included in ntddk.h

    PAGED_CODE();

    extendedInfo.Size = sizeof(extendedInfo);

    // Query for the process information
    Status = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &extendedInfo, sizeof(extendedInfo), nullptr);
    if (NT_SUCCESS(Status)) {
        *SecureProcess = (BOOLEAN)(extendedInfo.IsSecureProcess != 0);
    }

    return Status;
}


NTSTATUS IsProtectedProcess(_In_ HANDLE ProcessHandle, _Out_ BOOLEAN * ProtectedProcess)
/*
功能：检测进程是不是ProtectedProcess。

仿照IsSecureProcess而建。

注意适用的范围。
*/
{
    NTSTATUS Status{};
    PROCESS_EXTENDED_BASIC_INFORMATION extendedInfo = {0}; // definition included in ntddk.h

    PAGED_CODE();

    extendedInfo.Size = sizeof(extendedInfo);

    // Query for the process information
    Status = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &extendedInfo, sizeof(extendedInfo), nullptr);
    if (NT_SUCCESS(Status)) {
        *ProtectedProcess = (BOOLEAN)(extendedInfo.IsProtectedProcess != 0);
    }

    return Status;
}


NTSTATUS IsWow64Process(_In_ HANDLE ProcessHandle, _Out_ BOOLEAN * Wow64Process)
/*
功能：检测进程是不是Wow64Process。

仿照IsSecureProcess而建。

参数：
ProcessHandle是内核态的句柄，不是用户层的pid.

注意:
1.适用的范围。

另外的思路：
1.ZwQueryInformationProcess +　ProcessWow64Information
2.X64下仅有的PsGetProcessWow64Process(Process);
3.
*/
{
    NTSTATUS Status{};
    PROCESS_EXTENDED_BASIC_INFORMATION extendedInfo = {0}; // definition included in ntddk.h

    PAGED_CODE();

    extendedInfo.Size = sizeof(extendedInfo);

    // Query for the process information
    Status = ZwQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &extendedInfo, sizeof(extendedInfo), nullptr);
    if (NT_SUCCESS(Status)) {
        *Wow64Process = static_cast<BOOLEAN>(extendedInfo.IsWow64Process != 0);
    }

    return Status;
}


BOOLEAN IsWow64Process(_In_ HANDLE ProcessHandle)
{
    NTSTATUS Status{};
    BOOLEAN Wow64Process = FALSE;
    PEPROCESS Process = nullptr;
    HANDLE KernelHandle = nullptr;

    __try {
        Status = PsLookupProcessByProcessId(ProcessHandle, &Process);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsProcessType, KernelMode, &KernelHandle);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        Status = IsWow64Process(KernelHandle, &Wow64Process);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }
    } __finally {
        if (KernelHandle) {
            ZwClose(KernelHandle);
        }

        if (Process) {
            ObDereferenceObject(Process);
        }
    }

    return Wow64Process;
}


NTSTATUS AdjustPrivilege(ULONG Privilege, BOOLEAN Enable)
/*
功能：给当前进程（上下文所在的进程）提权。

用法示例：AdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE);

摘自：http://www.osronline.com/article.cfm?article=23
*/
{
    // Open current process token
    HANDLE tokenHandle{};
    NTSTATUS Status = ZwOpenProcessTokenEx(NtCurrentProcess(), TOKEN_ALL_ACCESS, OBJ_KERNEL_HANDLE, &tokenHandle);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("NtOpenProcessToken failed, Status 0x%x\n", Status);
        return Status;
    }

    // Set up the information about the privilege we are adjusting
    TOKEN_PRIVILEGES privSet{};
    privSet.PrivilegeCount = 1;
    privSet.Privileges[0].Luid = RtlConvertUlongToLuid(Privilege);
    if (Enable) {
        privSet.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        privSet.Privileges[0].Attributes = 0;
    }

    Status = ZwAdjustPrivilegesToken(tokenHandle,
                                     FALSE, // don't disable all privileges
                                     &privSet,
                                     sizeof(privSet),
                                     nullptr,  // old privileges - don't care
                                     nullptr); // returned length
    if (!NT_SUCCESS(Status)) {
        DbgPrint("ZwAdjustPrivilegesToken failed, Status 0x%x\n", Status);
    }

    (void)ZwClose(tokenHandle); // Close the process token handle

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int GetTokenOffsetInProcess()
/*
功能：获取Token在Process对象中的偏移量。

注意：此函数只能用在驱动的入口。

参考信息：
0: kd> ?? sizeof(nt!_eprocess)
unsigned int64 0xa40
0: kd> dt nt!_eprocess token
   +0x4b8 Token : _EX_FAST_REF
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    CLIENT_ID ClientId = {};
    OBJECT_ATTRIBUTES ob{};
    HANDLE ProcessHandle{};
    HANDLE TokenHandle{};
    int TokenOffset = 0;

    ClientId.UniqueProcess = PsGetCurrentProcessId();
    InitializeObjectAttributes(&ob, nullptr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    Status = ZwOpenProcess(&ProcessHandle, GENERIC_ALL, &ob, &ClientId);
    ASSERT(NT_SUCCESS(Status));

    Status = ZwOpenProcessTokenEx(ProcessHandle, TOKEN_ALL_ACCESS, OBJ_KERNEL_HANDLE, &TokenHandle);
    ASSERT(NT_SUCCESS(Status));

    PVOID ProcessObject = nullptr;
    Status = ObReferenceObjectByHandle(ProcessHandle, GENERIC_ALL, *PsProcessType, KernelMode, &ProcessObject, nullptr);
    ASSERT(NT_SUCCESS(Status));

    PVOID TokenObject = nullptr;
    Status = ObReferenceObjectByHandle(TokenHandle, TOKEN_ALL_ACCESS, *SeTokenObjectType, KernelMode, &TokenObject, nullptr);
    ASSERT(NT_SUCCESS(Status));

    size_t * ProcessObjectAddress = (size_t *)ProcessObject;
    size_t TokenObjectAddress = (size_t)TokenObject;

    for (int i = 0; i < 0xa00 / sizeof(size_t); i++) {
        size_t tmp = ProcessObjectAddress[i];
        tmp = tmp & ~0xf;
        if (tmp == TokenObjectAddress) {
            TokenOffset = i * sizeof(size_t);
            break;
        }
    }

    ObDereferenceObject(ProcessObject);
    ObDereferenceObject(TokenObject);
    Status = ZwClose(TokenHandle);
    Status = ZwClose(ProcessHandle);
    return TokenOffset;
}


DWORD GetProtectionOffsetInProcess()
/*
0: kd> dt _eprocess Protection
ntdll!_EPROCESS
   +0x87a Protection : _PS_PROTECTION

IDA信息：
PsGetProcessProtection                                                       ; Exported entry 1840. PsGetProcessProtection
PsGetProcessProtection
PsGetProcessProtection                                                       ; =============== S U B R O U T I N E =======================================
PsGetProcessProtection
PsGetProcessProtection
PsGetProcessProtection                                                       ; char __fastcall PsGetProcessProtection(_EPROCESS *Process)
PsGetProcessProtection                                                                       public PsGetProcessProtection
PsGetProcessProtection                                                       PsGetProcessProtection proc near        ; CODE XREF: NtQueryInformationProcess+2D11↓p
PsGetProcessProtection                                                                                               ; DATA XREF: .pdata:00000001400D8C18↑o ...
PsGetProcessProtection      000 8A 81 7A 08 00 00                                            mov     al, [rcx+87Ah]
PsGetProcessProtection+6    000 C3                                                           retn                    ; Return Near from Procedure
PsGetProcessProtection+6
PsGetProcessProtection+6                                                     PsGetProcessProtection endp
PsGetProcessProtection+6
PsGetProcessProtection+6                                                     ; ---------------------------------------------------------------------------

看到没？PsGetProcessProtection地址再加两个字节，后面的一个DWORD都是Protection在_EPROCESS中的偏移。

IDA伪码：
char __fastcall PsGetProcessProtection(_EPROCESS *Process)
{
  return Process->Protection.Level;
}
*/
{
    DWORD ProtectionOffset = 0;
    UNICODE_STRING SystemRoutineName = RTL_CONSTANT_STRING(L"PsGetProcessProtection");
    PBYTE PsGetProcessProtection = (PBYTE)MmGetSystemRoutineAddress(&SystemRoutineName);
    if (!PsGetProcessProtection) {
        return ProtectionOffset;
    }

    PsGetProcessProtection += 2;

    ProtectionOffset = *(PDWORD)PsGetProcessProtection;

    return ProtectionOffset;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
