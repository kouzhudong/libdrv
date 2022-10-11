#include "pch.h"
#include "object.h"
#include "Process.h"
#include "misc.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS GetObjectName(_In_ PVOID Object, _Inout_ PUNICODE_STRING ObjectName)
/*
���ܣ���ȡ���ֶ�������֣�ֻҪ���������֣����������ڻ�ȡע���ļ���������֡�

���ֵ��ڴ��ɵ������ͷš�

ע�ͣ��ļ���ע����ȡ�Ķ����ں�·����
*/
{
    POBJECT_NAME_INFORMATION ObjectNameInfo = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    if (NULL == Object || NULL == ObjectName) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitEmptyUnicodeString(ObjectName, NULL, 0);

    do {
        ULONG Length = 0;
        Status = ObQueryNameString(Object, NULL, Length, &Length);
        ASSERT(!NT_SUCCESS(Status));

        if (0 == Length) {
            //PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);//�кܶ������û�����ֵġ�
            break;
        }

        Length += sizeof(WCHAR);
        ObjectNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, Length, TAG);
        if (NULL == ObjectNameInfo) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        RtlZeroMemory(ObjectNameInfo, Length);

        Status = ObQueryNameString(Object, ObjectNameInfo, Length, &Length);
        if (!NT_SUCCESS(Status)) {
            //PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);//�кܶ������û�����ֵġ�
            break;
        }

        ObjectName->MaximumLength = ObjectNameInfo->Name.MaximumLength + sizeof(wchar_t);
        ObjectName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, ObjectName->MaximumLength, TAG);
        if (NULL == ObjectName->Buffer) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: %s", "ExAllocatePoolWithTag Fail");
            break;;
        }

        RtlZeroMemory(ObjectName->Buffer, ObjectName->MaximumLength);
        RtlCopyUnicodeString(ObjectName, &ObjectNameInfo->Name);
    } while (FALSE);

    if (ObjectNameInfo) {
        ExFreePoolWithTag(ObjectNameInfo, TAG);
    }

    return Status;
}


NTSTATUS GetObjectNtName(_In_ PVOID Object, _Inout_ PUNICODE_STRING NtName)
{
    ULONG length = MAXPATHLEN;
    PUNICODE_STRING Temp;
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING  KeyPath = {0};

    if (NULL == Object) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%p", Object);
        return STATUS_UNSUCCESSFUL;
    }

    Temp = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, length, TAG);//�������ͷš�
    if (Temp == 0) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ObQueryNameString(Object, (POBJECT_NAME_INFORMATION)Temp, length, &length);
    if (!NT_SUCCESS(Status)) {
        //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);//���Ҳ���١�
        ExFreePoolWithTag(Temp, TAG);
        return Status;
    }

    RtlInitUnicodeString(&KeyPath, Temp->Buffer);

    NtName->MaximumLength = KeyPath.MaximumLength + sizeof(wchar_t);
    NtName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, NtName->MaximumLength, TAG);//WorkItem��ɺ��ͷš�
    if (0 == NtName->Buffer) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
        ExFreePoolWithTag(Temp, TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(NtName->Buffer, NtName->MaximumLength);
    RtlCopyUnicodeString(NtName, &KeyPath);

    ExFreePoolWithTag(Temp, TAG);

    return Status;
}


NTSTATUS GetFileObjectDosName(_In_ PFILE_OBJECT FileObject, _Inout_ PUNICODE_STRING DosName)
{
    NTSTATUS Status = STATUS_SUCCESS;
    POBJECT_NAME_INFORMATION FileNameInfo = NULL;

    if (NULL == FileObject) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%p", FileObject);
        return STATUS_UNSUCCESSFUL;
    }

    Status = IoQueryFileDosDeviceName(FileObject, &FileNameInfo);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return Status;
    }

    DosName->MaximumLength = FileNameInfo->Name.MaximumLength + sizeof(wchar_t);
    DosName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, DosName->MaximumLength, TAG);
    if (0 == DosName->Buffer) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(DosName->Buffer, DosName->MaximumLength);
    RtlCopyUnicodeString(DosName, &FileNameInfo->Name);

    ExFreePool(FileNameInfo);

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


void GetKnownDllPath()
/*
���ܣ���ȡ\\KnownDlls\\KnownDllPath��ֵ��

ע��64λ�»��и�\\KnownDlls\\KnownDllPath32������ʵ�Ǹ��������ӡ�
*/
{
    ULONG ActualLength;
    HANDLE LinkHandle;
    WCHAR NameBuffer[128] = {0};//������ܶ����С��.
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING LinkString, NameString;

    LinkString.Buffer = NameBuffer;
    LinkString.MaximumLength = sizeof(NameBuffer);
    RtlInitUnicodeString(&NameString, L"\\KnownDlls\\KnownDllPath");//��������//,��Ȼ��ZwOpenSymbolicLinkObject����ʧ��.���ǵõ��ľ��Ϊ0.
    InitializeObjectAttributes(&ObjectAttributes, &NameString, OBJ_KERNEL_HANDLE, NULL, NULL);
    ZwOpenSymbolicLinkObject(&LinkHandle, SYMBOLIC_LINK_QUERY, &ObjectAttributes);

    ZwQuerySymbolicLinkObject(LinkHandle, &LinkString, &ActualLength);//LinkString������Ҫ��ֵ.
    KdPrint(("KnownDllPath: %wZ \n", &LinkString));

    ZwClose(LinkHandle);
}


void GetKnownDllPathEx()
/*
���ܣ���ȡ\\KnownDlls\\KnownDllPath��ֵ��

ע��64λ�»��и�\\KnownDlls\\KnownDllPath32������ʵ�Ǹ��������ӡ�
*/
{
    UNICODE_STRING usDirName, usSymbolicName, usSymbolic;
    OBJECT_ATTRIBUTES ObjDir, ObjSymbolic;
    WCHAR wchBuffer[128];
    HANDLE hDir, hSymbolic;

    RtlInitUnicodeString(&usDirName, L"\\KnownDlls");
    InitializeObjectAttributes(&ObjDir, &usDirName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &ObjDir);

    RtlInitUnicodeString(&usSymbolicName, L"KnownDllPath");
    InitializeObjectAttributes(&ObjSymbolic, &usSymbolicName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hDir, NULL);
    ZwOpenSymbolicLinkObject(&hSymbolic, GENERIC_READ, &ObjSymbolic);

    usSymbolic.Buffer = wchBuffer;
    usSymbolic.MaximumLength = 256 * sizeof(WCHAR);
    usSymbolic.Length = 0;
    ZwQuerySymbolicLinkObject(hSymbolic, &usSymbolic, NULL);
    KdPrint(("KnownDllPath: %wZ \n", &usSymbolic));
}


void GetSystemRootPathName(PUNICODE_STRING PathName,
                           PUNICODE_STRING NtPathName,
                           PUNICODE_STRING DosPathName
)
/*
���ܣ���Ҫ�ǻ�ȡL"\\SystemRoot"��NT��DOS·��������Ҳ���Ի�ȡ��L"\\SystemRoot"��ͷ���κκϷ��Ҵ��ڵ�·����

���磺���ֱ�ӻ�ȡ�����ļ��ģ�NT��DOS�ģ�·����������Ӳ�����ˡ�
1.L"\\SystemRoot"
2.L"\\SystemRoot\\System32\\ntdll.dll"
3.L"\\SystemRoot\\System32\\smss.exe"
4.L"\\SystemRoot\\System32\\csrss.exe"
5.�ȵȡ�
*/
{
    HANDLE File;
    NTSTATUS st;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus;
    PFILE_OBJECT FileObject;
    UNICODE_STRING FullName = {0};
    POBJECT_NAME_INFORMATION FileNameInfo = NULL;

    // Initialize the system DLL
    InitializeObjectAttributes(&ObjectAttributes, PathName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenFile(&File, SYNCHRONIZE | FILE_READ_DATA, &ObjectAttributes, &IoStatus, FILE_SHARE_READ, 0);
    ASSERT(NT_SUCCESS(st));

    st = ObReferenceObjectByHandle(File, FILE_READ_ACCESS, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, 0);
    ASSERT(NT_SUCCESS(st));

    st = GetObjectNtName(FileObject, &FullName);
    ASSERT(NT_SUCCESS(st));
    if (NULL == FullName.Buffer) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
    } else {
        //KdPrint(("NT name:%wZ.\r\n", &FullName));
        RtlCopyUnicodeString(NtPathName, &FullName);

        st = IoQueryFileDosDeviceName(FileObject, &FileNameInfo);
        ASSERT(NT_SUCCESS(st));

        //KdPrint(("dos name:%wZ.\r\n", &FileNameInfo->Name));
        RtlCopyUnicodeString(DosPathName, &FileNameInfo->Name);

        ExFreePool(FileNameInfo);
        ExFreePoolWithTag(FullName.Buffer, TAG);
    }

    ObDereferenceObject(FileObject);
    ZwClose(File);
}


NTSTATUS GetSystemRootName(_In_ PUNICODE_STRING SymbolicLinkName, 
                           _Inout_ PUNICODE_STRING NtPathName, 
                           _Inout_ PUNICODE_STRING DosPathName
)
/*
���ܣ���Ҫ�ǻ�ȡL"\\SystemRoot"��NT��DOS·��������Ҳ���Ի�ȡ��L"\\SystemRoot"��ͷ���κκϷ��Ҵ��ڵ�·����

ע�⣺SymbolicLinkName�������Ѿ�����·�����ļ���

���磺���ֱ�ӻ�ȡ�����ļ��ģ�NT��DOS�ģ�·����������Ӳ�����ˡ�
1.L"\\SystemRoot"
2.L"\\SystemRoot\\System32\\ntdll.dll"
3.L"\\SystemRoot\\System32\\smss.exe"
4.L"\\SystemRoot\\System32\\csrss.exe"
5.�ȵȡ�
*/
{
    HANDLE File = NULL;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus;
    PFILE_OBJECT FileObject = NULL;
    POBJECT_NAME_INFORMATION FileNameInfo = NULL;

    PAGED_CODE();

    if (NULL == SymbolicLinkName || NULL == NtPathName || NULL == DosPathName) {
        return STATUS_INVALID_PARAMETER;
    }

    do {
        InitializeObjectAttributes(&ObjectAttributes, SymbolicLinkName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        Status = ZwOpenFile(&File, SYNCHRONIZE | FILE_READ_DATA, &ObjectAttributes, &IoStatus, FILE_SHARE_READ, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        Status = ObReferenceObjectByHandle(File, FILE_READ_ACCESS, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        Status = GetObjectName(FileObject, NtPathName);
        if (!NT_SUCCESS(Status) || NULL == NtPathName->Buffer) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        //KdPrint(("NT name:%wZ.\r\n", &NtPathName));

        Status = IoQueryFileDosDeviceName(FileObject, &FileNameInfo);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        DosPathName->MaximumLength = FileNameInfo->Name.Length;
        Status = AllocateUnicodeString(DosPathName);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        //KdPrint(("dos name:%wZ.\r\n", &FileNameInfo->Name));
        RtlCopyUnicodeString(DosPathName, &FileNameInfo->Name);
    } while (FALSE);

    if (FileNameInfo) {
        ExFreePool(FileNameInfo);
    }

    if (FileObject) {
        ObDereferenceObject(FileObject);
    }

    if (File) {
        ZwClose(File);
    }

    if (!NT_SUCCESS(Status)) {
        FreeUnicodeString(NtPathName);
        FreeUnicodeString(DosPathName);
    }

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS ZwEnumerateObject(_In_ PUNICODE_STRING Directory)
/*
���ܣ�ö��һ��DirectoryObject�µĶ���
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob;
    HANDLE FileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    PVOID FileInformation = 0;
    ULONG Length = sizeof(FILE_DIRECTORY_INFORMATION);//��������õ�̫С�ᵼ��ZwQueryDirectoryFile������    
    BOOLEAN           RestartScan;
    ULONG             Context = 0;
    ULONG             ReturnedLength;
    UNICODE_STRING driver = RTL_CONSTANT_STRING(L"Driver");

    InitializeObjectAttributes(&ob, Directory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenDirectoryObject(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ob);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return Status;
    }

    Length = Length + 520;//Ϊ�μ�������֣��뿴ZwEnumerateFile1��˵����
    FileInformation = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
    if (FileInformation == NULL) {
        Status = STATUS_UNSUCCESSFUL;
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ZwClose(FileHandle);
        return Status;
    }
    RtlZeroMemory(FileInformation, Length);

    //RestartScan = FALSE;//ΪTRUE�ᵼ����ѭ��;
    //Status = ZwQueryDirectoryObject( FileHandle, FileInformation, Length, TRUE, RestartScan, &Context, &ReturnedLength );
    //if (!NT_SUCCESS (Status)) //��ʱҲ��õ����ݡ�
    //{
    //    Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);//STATUS_BUFFER_TOO_SMALL == C0000023
    //    ExFreePoolWithTag(FileInformation, TAG);
    //    ZwClose(FileHandle);
    //    return Status;
    //}

    do {
        UNICODE_STRING FileName = {0};
        POBJECT_DIRECTORY_INFORMATION podi = 0;
        UNICODE_STRING FullName = {0};

        RestartScan = FALSE;//ΪTRUE�ᵼ����ѭ��;
        Status = ZwQueryDirectoryObject(FileHandle, FileInformation, Length, TRUE, RestartScan, &Context, &ReturnedLength);
        if (Status != STATUS_NO_MORE_FILES && Status != STATUS_SUCCESS) {
            break;//�������û���߹���
        }

        podi = (POBJECT_DIRECTORY_INFORMATION)FileInformation;

        //������������ͷŹ���
        if (RtlCompareUnicodeString(&podi->TypeName, &driver, TRUE) != 0) {
            continue;
        }

        //����Ҫ��ʾ���ڴ棬��һ˼·�Ǹ�ʽ����
        FullName.MaximumLength = (USHORT)Length + Directory->MaximumLength;
        FullName.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, FullName.MaximumLength, TAG);
        if (FullName.Buffer == NULL) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlZeroMemory(FullName.Buffer, FullName.MaximumLength);

        RtlCopyUnicodeString(&FullName, Directory);

        Status = RtlAppendUnicodeToString(&FullName, L"\\");
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            ExFreePoolWithTag(FullName.Buffer, TAG);
            break;
        }

        Status = RtlAppendUnicodeStringToString(&FullName, &podi->Name);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            ExFreePoolWithTag(FullName.Buffer, TAG);
            break;
        }

        //KdPrint(("NtName %wZ\n", &podi->NtName));  
        KdPrint(("Name %wZ\n", &FullName));

        ExFreePoolWithTag(FullName.Buffer, TAG);
    } while (Status != STATUS_NO_MORE_FILES);

    if (STATUS_NO_MORE_FILES == Status) {
        Status = STATUS_SUCCESS;
    }

    if (FileInformation) {
        ExFreePoolWithTag(FileInformation, TAG);
        FileInformation = NULL;
    }

    ZwClose(FileHandle);

    return Status;
}


NTSTATUS ZwEnumerateDriverObject()
/*
���ܣ�ö��ϵͳ����������
�ǵã���һ����������ʵ�ִ˹��ܣ���ʱ��������ö��ϵͳ��ģ�飬���Ե�ʱû��ע���Ǹ��������������벻���ˣ�һ���ּ����ȥ�ˡ�
      �ǵ�devicetree����ͨ��ö��driver��FileSystem�µĶ���ʵ�ֵģ�������WINOBJ�����ƵĶ��������Ҳ��ͨ����ʵ�ֵġ�
      ����ZwQueryDirectoryObject�Ĺ���Ӧ�ò�С������΢����Ӧ�ò��Ѿ������˺��������ں�ʹ�ô˺���Ӧ��û�����⡣
˵����FileSystem����Ȼ������Ŀ¼���󣬵�����û������������û�еݹ顣����ԭ��ҲӦ��û�С�
      �����ɶ�ô��أ���Ϊ������NTģ�飨�����Ǹ�����NTOS*.EXE����HAL.DLL(Ҳ�����������͵�)��
      ���Կ��Ը��ݴ����������һ����ȡ�ַ��������豸����Ȳ�����
      �˲���ֻ�жϴ��ڣ����µĻ�Ҫ�Լ����֡�

made by correy
made at 2015.05.19
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING directory = RTL_CONSTANT_STRING(L"\\driver");
    UNICODE_STRING FileSystem = RTL_CONSTANT_STRING(L"\\FileSystem");

    Status = ZwEnumerateObject(&directory);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = ZwEnumerateObject(&FileSystem);

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#if (NTDDI_VERSION >= NTDDI_VISTA)
void EnumerateTransactionObject()
/*
����KTMOBJECT_RESOURCE_MANAGER��KTMOBJECT_ENLISTMENT������£�ZwEnumerateTransactionObject�ĵ�һ����������ΪNULL�����߷���STATUS_INVALID_HANDLE��
����KTMOBJECT_TRANSACTION����һ�������Ϊ�գ�����һ�ε��ö�����STATUS_NO_MORE_ENTRIES��
17:22 2019/7/30
*/
{
    NTSTATUS Status;
    KTMOBJECT_CURSOR Cursor = {0};
    ULONG ReturnedBytes;

    for (int x = 0; ; x++) {
        Status = ZwEnumerateTransactionObject(NULL, KTMOBJECT_TRANSACTION, &Cursor, sizeof(Cursor), &ReturnedBytes);
        if (STATUS_NO_MORE_ENTRIES == Status) {
            break;
        }

        if (STATUS_SUCCESS != Status) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            break;
        }

        KdPrint(("x:%d.\r\n", x));
    }


    for (int x = 0; ; x++) {
        Status = ZwEnumerateTransactionObject(NULL, KTMOBJECT_TRANSACTION_MANAGER, &Cursor, sizeof(Cursor), &ReturnedBytes);
        if (STATUS_NO_MORE_ENTRIES == Status) {
            break;
        }

        if (STATUS_SUCCESS != Status) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            break;
        }

        ASSERT(Cursor.ObjectIdCount == 1);

        KdPrint(("x:%d.\r\n", x));
    }
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS ZwQueryObjectNameByHandle(IN HANDLE Handle, OUT PUNICODE_STRING ObjectName)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVOID Object;
    KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
    ULONG  Length = 1024;//ȡ�������ԭ��:�ο�ObQueryNameString�����ĵ�����������˵��:A reasonable size for the buffer to accommodate most object names is 1024 bytes. 
    POBJECT_NAME_INFORMATION pu = 0;

    Status = ObReferenceObjectByHandle(Handle, 0, NULL, PreviousMode, &Object, 0);
    if (!NT_SUCCESS(Status)) {
        return(Status);
    }

    Length = 0;
    Status = ObQueryNameString(Object, pu, 0, &Length);
    if (Status != STATUS_INFO_LENGTH_MISMATCH) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ObDereferenceObject(Object);
        return Status;
    }

    Length += 512;
    pu = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
    if (pu == 0) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ObDereferenceObject(Object);
        return Status;
    }
    RtlZeroMemory(pu, Length);

    Status = ObQueryNameString(Object, pu, Length, &Length);
    if (Status != STATUS_SUCCESS) {
        /*
        �����ʱ�ķ���ֵ��0xC0000001��
        ������ϵͳ�ϵ��豸û�з������á�
        ��ʱ�ľ�����������ļ���
        ����process explorerҲ����ʾ����û��ֵ�ġ�
        */
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(pu, TAG);
        ObDereferenceObject(Object);
        return Status;
    }

    ObDereferenceObject(Object);

    //�еĶ�����û�����ֵġ�
    if (pu->Name.Length == 0) {
        Status = STATUS_UNSUCCESSFUL;
    } else {
        RtlCopyUnicodeString(ObjectName, &pu->Name);
        //ObjectName->Buffer = pu->Name.Buffer;
        //ObjectName->Length = pu->Name.Length;
        //ObjectName->MaximumLength = pu->Name.MaximumLength;
    }

    ExFreePoolWithTag(pu, TAG);

    return Status;
}


NTSTATUS EnumerateProcessHandles(IN HANDLE Pid, OUT PDWORD ProcessHandles)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    DWORD nSize = 4096, nReturn;
    PSYSTEM_HANDLE_INFORMATION pSysHandleInfo;
    CLIENT_ID   ClientId = {0};//����ʼ��ZwOpenProcess�����⡣
    HANDLE  ProcessHandle;
    DWORD dwhandles = 0;//һ�����̵����еľ��������
    ULONG i = 0;
    OBJECT_ATTRIBUTES ob;

    pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, nSize, TAG);
    if (pSysHandleInfo == NULL) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pSysHandleInfo, nSize);
    while (ZwQuerySystemInformation(SystemHandleInformation, pSysHandleInfo, nSize, &nReturn) == STATUS_INFO_LENGTH_MISMATCH)// Get system handle information.
    {
        ExFreePoolWithTag(pSysHandleInfo, TAG);
        nSize += 4096;
        pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, nSize, TAG);
        if (pSysHandleInfo == NULL) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(pSysHandleInfo, nSize);
    }

    ClientId.UniqueProcess = Pid;
    InitializeObjectAttributes(&ob, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenProcess(&ProcessHandle, GENERIC_ALL, &ob, &ClientId);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag(pSysHandleInfo, TAG);
        return Status;
    }

    for (; i < pSysHandleInfo->NumberOfHandles; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO pHandle = &(pSysHandleInfo->Handles[i]);

        //���ݽ��̽���������
    #pragma prefast(push)
    #pragma warning(disable:4302)
    //#pragma prefast(disable:4302, "������ǿ��ת����: �ӡ�HANDLE������USHORT���ض�")
        if (pHandle->UniqueProcessId == (USHORT)Pid)
        #pragma prefast(pop)        
        {
            HANDLE hCopy;// Duplicate the handle in the current process
            PVOID  ObjectInformation = 0;
            ULONG  ObjectInformationLength = 0;
            ULONG  ReturnLength = 0;
            PPUBLIC_OBJECT_TYPE_INFORMATION ppoti = 0;
            UNICODE_STRING object_name;

            dwhandles++;	// Increase the number of handles

            /*
            ����ϵͳ�����о������Ϊ���̵�IDLE����᷵��0xc0000022.���ܾ����ʡ�
            process explorerҲ����ˡ���������ʾ��PSYSTEM_HANDLE_TABLE_ENTRY_INFO�����ݡ�
            pchunterû����ʾ���Ϊ���̺��̵߳���Ϣ������process explorer�ܡ�
            process explorerĬ�ϵ�������ǲ���ʾû�����ֵľ����MAPPINGS�ġ����ǿ������ú��޸ġ�
            */
            Status = ZwDuplicateObject(ProcessHandle,
                                       (HANDLE)pHandle->HandleValue,
                                       NtCurrentProcess(),
                                       &hCopy,
                                       PROCESS_ALL_ACCESS,
                                       FALSE,
                                       DUPLICATE_SAME_ACCESS);
            if (!NT_SUCCESS(Status)) {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
                continue;
            }

            //Status = ZwQueryObject(hCopy, ObjectTypeInformation, ObjectInformation, ObjectInformationLength, &ReturnLength);
            //if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
            //{
            //    ObjectInformationLength = ReturnLength;
            //}
            //else
            //{
            //    //continue;
            //    break;//���򷢳����������Ȳ���ȷ�� C0000004
            //}

            //��ѯ������ͣ������ַ�����
            ObjectInformationLength = sizeof(PUBLIC_OBJECT_TYPE_INFORMATION) * 2;//���Ӧ�������ӵ㡣�Ӹ�512Ӧ�ú��ʵ㡣             
            ObjectInformation = ExAllocatePoolWithTag(NonPagedPool, ObjectInformationLength, TAG);
            if (ObjectInformation == NULL) {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
                ZwClose(hCopy);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            RtlZeroMemory(ObjectInformation, ObjectInformationLength);
            Status = ZwQueryObject(hCopy,
                                   ObjectTypeInformation,
                                   ObjectInformation,
                                   ObjectInformationLength,
                                   &ReturnLength);
            if (!NT_SUCCESS(Status)) {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
                ExFreePoolWithTag(ObjectInformation, TAG);
                ZwClose(hCopy);
                return Status;
            }

            object_name.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH, TAG);
            if (object_name.Buffer == 0) {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
                ExFreePoolWithTag(ObjectInformation, TAG);
                ZwClose(hCopy);
                return Status;
            }
            RtlZeroMemory(object_name.Buffer, MAX_PATH);
            RtlInitEmptyUnicodeString(&object_name, object_name.Buffer, MAX_PATH);

            ppoti = (PPUBLIC_OBJECT_TYPE_INFORMATION)ObjectInformation;

            /*
            ���Ҫ��ѯ�����ֵ�����֣����ԣ�
            1.��ZwQueryObject��δ������ObjectNameInformation����ʵ����ʹ��ObReferenceObjectByHandle+ObpQueryNameStringʵ�ֵġ�
            2.ObReferenceObjectByHandle+ObQueryNameString��
            */
            Status = ZwQueryObjectNameByHandle(hCopy, &object_name);
            if (NT_SUCCESS(Status)) {
                KdPrint(("HANDLE:0x%x, TYPE:%wZ, NAME:%wZ\n", pHandle->HandleValue, &ppoti->TypeName, &object_name));
                RtlFreeUnicodeString(&object_name);
                //ExFreePoolWithTag(object_name.Buffer, tag );
            } else {
                KdPrint(("HANDLE:0x%x, TYPE:%wZ\n", pHandle->HandleValue, &ppoti->TypeName));
            }

            Status = ZwClose(hCopy);
            //if (!NT_SUCCESS(Status))
            //{//�еľ�������������ǲ�׼�رյġ�
            //    Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
            //    ExFreePoolWithTag( pSysHandleInfo, tag );
            //    ExFreePoolWithTag( ObjectInformation, tag );
            //    return Status;
            //}

            ExFreePoolWithTag(ObjectInformation, TAG);
        }
    }

    Status = ZwClose(ProcessHandle);
    /*if (!NT_SUCCESS(Status)) {//�����еľ���Ѿ��ͷ��ˡ�
        Print(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        ExFreePoolWithTag( pSysHandleInfo, tag );
        return Status;
    } */

    ExFreePoolWithTag(pSysHandleInfo, TAG);

    *ProcessHandles = dwhandles;

    return Status;
}


NTSTATUS EnumerateSystemProcessHandles()
/*
�ں˰��ö��ϵͳ/���̵ľ��������Ϣ�Ĵ��롣

made by correy
made at 2014.06.26
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    DWORD process_handle = 0;
    HANDLE test_handle = PsGetProcessId(PsInitialSystemProcess);

    Status = AdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return Status;
    }

    Status = EnumerateProcessHandles(test_handle, &process_handle);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        return Status;
    }

    return Status;//STATUS_SUCCESS
}


//////////////////////////////////////////////////////////////////////////////////////////////////
