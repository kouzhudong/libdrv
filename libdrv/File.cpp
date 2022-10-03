#include "pch.h"
#include "File.h"
#include "misc.h"
#include "object.h"


#pragma warning(disable:6386)
#pragma warning(disable:6387)
#pragma warning(disable:6011)
#pragma warning(disable:6385)
#pragma warning(disable:28175)
#pragma warning(disable:4996)


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
���ܣ��������б���/ö���ļ���

����һ���򵥲�ֵһ���Ĺ��ܣ���������һ���ʱ�䣬Ҳ����̫���������д˼�¼��

made by correy
made at 2014.06.04
*/


NTSTATUS ZwEnumerateFile(IN UNICODE_STRING * directory)
/*
���ܣ�ö��Ŀ¼�µ��ļ���û�еݹ顣

���������������·����������ļ�������������޸�,���������ļ�·����

·���ĸ�ʽ����ǣ�L"\\??\\C:\\Windows");
����"\Device\HarddiskVolume1\XXX  \\DosDevices\\C:\\����Ȼ����ת�����ṹ����õ�UNICODE_STRING��������ȫ��

���������˼·��һ�¶�ȡ��һ��Ŀ¼�µ�������Ϣ����ȱ���ǲ��Զ����ģ�����������ڴ�Ĵ�С����֪����

��ʵ��ZwEnumerateFile�������û�л�ȡ������ڴ�Ĵ�С�Ĺ��ܣ�һ��˼·�ǽṹ�Ĵ�С��·���Ĵ�С��
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob;
    HANDLE FileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    PVOID FileInformation = 0;
    ULONG Length = sizeof(FILE_DIRECTORY_INFORMATION);//��������õ�̫С�ᵼ��ZwQueryDirectoryFile������
    FILE_DIRECTORY_INFORMATION * fibdi = 0;

    InitializeObjectAttributes(&ob, directory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenFile(&FileHandle,
                        GENERIC_READ | SYNCHRONIZE,
                        &ob,
                        &IoStatusBlock,
                        FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND || IoStatusBlock.Information == FILE_DOES_NOT_EXIST) {
            KdPrint(("file does not exist\n"));
        }
        return Status;
    }

    do {
        if (FileInformation) {
            ExFreePoolWithTag(FileInformation, TAG);
            FileInformation = NULL;
        }

        FileInformation = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
        if (FileInformation == NULL) {
            Status = STATUS_UNSUCCESSFUL;
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
            ZwClose(FileHandle);
            return Status;
        }
        RtlZeroMemory(FileInformation, Length);

        Status = ZwQueryDirectoryFile(FileHandle,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &IoStatusBlock,
                                      FileInformation,
                                      Length,
                                      FileDirectoryInformation,
                                      FALSE,
                                      NULL,
                                      TRUE);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);//STATUS_BUFFER_TOO_SMALL == C0000023
            //return Status;
        }

        Length *= 2;
    } while (!NT_SUCCESS(Status));

    for (fibdi = (FILE_DIRECTORY_INFORMATION *)FileInformation;
         ;
         fibdi = (FILE_DIRECTORY_INFORMATION *)((char *)fibdi + fibdi->NextEntryOffset)) {
        UNICODE_STRING FileName = {0};

        if (FILE_ATTRIBUTE_DIRECTORY == fibdi->FileAttributes) {
            //������Կ��ǵݹ顣����������ļ��е���ʾ��
            continue;
        }

        FileName.Buffer = fibdi->FileName;
        FileName.Length = (USHORT)fibdi->FileNameLength;
        FileName.MaximumLength = FileName.Length + 2;

        KdPrint(("FileName %wZ\n", &FileName));

        if (fibdi->NextEntryOffset == 0) {
            break;
        }
    }

    if (FileInformation) {
        ExFreePoolWithTag(FileInformation, TAG);
        FileInformation = NULL;
    }

    ZwClose(FileHandle);

    return Status;
}


NTSTATUS ZwEnumerateFileEx(IN UNICODE_STRING * directory)
/*
���ܣ�ö��Ŀ¼�µ��ļ���û�еݹ顣

���������������·����������ļ�������������޸�,���������ļ�·����

·���ĸ�ʽ����ǣ�L"\\??\\C:\\Windows");
����"\Device\HarddiskVolume1\XXX  \\DosDevices\\C:\\����Ȼ����ת�����ṹ����õ�UNICODE_STRING��������ȫ��

����ǸĽ��档
��Ϊ����ĺ�����������ȷ��Ŀ¼���ж���Ŀ¼����ϵͳĿ¼���м�ǧ���ļ���
����취��һ��һ�����ģ��ο���KMDKIT�ĵ�ʮһ�½̡̳�
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob;
    HANDLE FileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    PVOID FileInformation = 0;
    ULONG Length = sizeof(FILE_DIRECTORY_INFORMATION);//��������õ�̫С�ᵼ��ZwQueryDirectoryFile������

    InitializeObjectAttributes(&ob, directory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenFile(&FileHandle,
                        GENERIC_READ | SYNCHRONIZE,
                        &ob,
                        &IoStatusBlock,
                        FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND || IoStatusBlock.Information == FILE_DOES_NOT_EXIST) {
            KdPrint(("file does not exist\n"));
        }
        return Status;
    }

    Length = Length + 520;//Ϊ�μ�������֣��뿴ZwEnumerateFile1��˵����
    FileInformation = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
    if (FileInformation == NULL) {
        Status = STATUS_UNSUCCESSFUL;
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
        ZwClose(FileHandle);
        return Status;
    }
    RtlZeroMemory(FileInformation, Length);

    Status = ZwQueryDirectoryFile(FileHandle,
                                  NULL,
                                  NULL,
                                  NULL,
                                  &IoStatusBlock,
                                  FileInformation,
                                  Length,
                                  FileDirectoryInformation,
                                  TRUE,
                                  NULL,
                                  TRUE);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);//STATUS_BUFFER_TOO_SMALL == C0000023
        ExFreePoolWithTag(FileInformation, TAG);
        ZwClose(FileHandle);
        return Status;
    }

    do {
        UNICODE_STRING FileName = {0};
        FILE_DIRECTORY_INFORMATION * fibdi = 0;

        Status = ZwQueryDirectoryFile(FileHandle,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &IoStatusBlock,
                                      FileInformation,
                                      Length,
                                      FileDirectoryInformation,
                                      TRUE,
                                      NULL,
                                      FALSE);
        if (Status != STATUS_NO_MORE_FILES && Status != STATUS_SUCCESS) {
            break;//�������û���߹���
        }

        fibdi = (FILE_DIRECTORY_INFORMATION *)FileInformation;

        if (FILE_ATTRIBUTE_DIRECTORY == fibdi->FileAttributes) {
            //������Կ��ǵݹ顣����������ļ��е���ʾ��
            continue;
        }

        FileName.Buffer = fibdi->FileName;
        FileName.Length = (USHORT)fibdi->FileNameLength;
        FileName.MaximumLength = FileName.Length + 2;

        KdPrint(("FileName %wZ\n", &FileName));

    } while (Status != STATUS_NO_MORE_FILES);

    if (FileInformation) {
        ExFreePoolWithTag(FileInformation, TAG);
        FileInformation = NULL;
    }

    ZwClose(FileHandle);

    return Status;
}


/*
    //�����ԣ����������͵�·�����ǿ��Եġ�
    UNICODE_STRING directory  = RTL_CONSTANT_STRING(L"\\??\\C:\\test");
    //UNICODE_STRING directory  = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\test");
    //UNICODE_STRING directory  = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\test");

    ע�⣺
    \\Device\\HarddiskVolume1\\�ǿ��Եģ�
    \\Device\\HarddiskVolume1�ǲ����Եġ�

    ZwEnumerateFileEx(&directory);//, FileIdBothDirectoryInformation
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID NTAPI WriteDiskSector(INT DiskIndex, LONGLONG StartingOffset, PVOID Buffer, ULONG Length)
/*
���ܣ�д���̵�������

������
DiskIndex:����������
StartingOffset��д��λ�ã����ֽ�Ϊ��λ���������߽���롣
Buffer�������ı�����
Length�������ı�����

ע�⣺
1.���û������FileObject����Windows 10�ϣ���������������fileinfo!FIPreReadWriteCallback�ڵ���nt!FsRtlIsPagingFileʱ��
2.�˺�����Windows 10�ϻ�ʧ�ܡ�
3.д��һ������֮���������ʧ�ܡ�
*/
{
    LARGE_INTEGER partitionTableOffset = {0};
    KEVENT event;
    IO_STATUS_BLOCK ioStatus;
    PIRP irp;
    NTSTATUS Status = STATUS_SUCCESS;
    wchar_t deviceNameBuffer[128];
    UNICODE_STRING ObjectName;
    PDEVICE_OBJECT DeviceObject;//�豸L"\\Device\\Harddisk%d\\DR%d" ���� ��������L"\\Device\\Harddisk%d\\Partition0" ������Ķ���
    PFILE_OBJECT FileObject;

    _swprintf(deviceNameBuffer, L"\\Device\\Harddisk%d\\Partition0", DiskIndex);
    //_swprintf(deviceNameBuffer, L"\\Device\\Harddisk%d\\DR%d", index, index);
    RtlInitUnicodeString(&ObjectName, deviceNameBuffer);
    Status = IoGetDeviceObjectPointer(&ObjectName, FILE_ALL_ACCESS, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    partitionTableOffset.QuadPart = StartingOffset;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE,
                                       DeviceObject,
                                       Buffer,
                                       Length,
                                       &partitionTableOffset,
                                       &event,
                                       &ioStatus);
    if (!irp) {
        ObDereferenceObject(FileObject);
        return;
    } else {
        PIO_STACK_LOCATION irpStack;
        irpStack = IoGetNextIrpStackLocation(irp);
        irpStack->FileObject = FileObject;//https://community.osr.com/discussion/34920/how-to-use-iobuildsynchronousfsdrequest-to-read-a-disk-file
        irpStack->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
    }

    Status = IoCallDriver(DeviceObject, irp);
    if (Status == STATUS_PENDING) {
        (VOID)KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL);
        Status = ioStatus.Status;
    }

    if (!NT_SUCCESS(Status)) {

    }

    ObDereferenceObject(FileObject);
}


VOID NTAPI ReadMBR(IN PDEVICE_OBJECT DeviceObject, IN ULONG SectorSize, OUT PVOID * Buffer)
{
    LARGE_INTEGER partitionTableOffset;
    PUCHAR readBuffer = (PUCHAR)NULL;
    KEVENT event;
    IO_STATUS_BLOCK ioStatus;
    PIRP irp;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG readSize;

    *Buffer = NULL;

    if (SectorSize >= 512) {
        readSize = SectorSize;
    } else {
        readSize = 512;
    }

#pragma warning(push)
#pragma warning(disable:4996)//������Ϊ�ѷ��
    partitionTableOffset = RtlConvertUlongToLargeInteger(0);// Start at sector 0 of the device.    
#pragma warning(pop)    
    readBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolCacheAligned,
                                               PAGE_SIZE > readSize ? PAGE_SIZE : readSize,
                                               'btsF');// Allocate a buffer that will hold the reads.
    if (readBuffer == NULL) {
        return;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ,
                                       DeviceObject,
                                       readBuffer,
                                       readSize,
                                       &partitionTableOffset,
                                       &event,
                                       &ioStatus);
    if (!irp) {
        ExFreePool(readBuffer);
        return;
    } else {
        PIO_STACK_LOCATION irpStack;
        irpStack = IoGetNextIrpStackLocation(irp);
        irpStack->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
    }

    Status = IoCallDriver(DeviceObject, irp);
    if (Status == STATUS_PENDING) {
        (VOID)KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER)NULL);
        Status = ioStatus.Status;
    }

    if (!NT_SUCCESS(Status)) {
        ExFreePool(readBuffer);
        return;
    }

    *Buffer = readBuffer;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS FltGetFileNameInformationEx(__inout PFLT_CALLBACK_DATA Cbd,
                                     __in PCFLT_RELATED_OBJECTS FltObjects,
                                     OUT PUNICODE_STRING usFullPath
)
/*
д���������ԭ���ǣ�FltGetFileNameInformation���ڲ����ڵ�·���᷵��ʧ�ܡ�
Ҳ��Ӧ����������ʵ�����Ҳ����취�ˡ�
�����ʵ�ְ취�ǣ���������ʧ�ܣ��ͻ�ȡ�ļ���������ݡ�
*/
{
    PFLT_FILE_NAME_INFORMATION pfni;
    NTSTATUS Status = STATUS_SUCCESS;

    //�����ɹ��ˣ��������ͷš�
    usFullPath->Buffer = (wchar_t *)ExAllocatePoolWithTag(NonPagedPool, MAXPATHLEN, TAG);
    if (usFullPath->Buffer == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    RtlZeroMemory(usFullPath->Buffer, MAXPATHLEN);
    RtlInitEmptyUnicodeString(usFullPath, usFullPath->Buffer, MAXPATHLEN);//Ч����ֻ�Ǹı����ֵ,����ṹ��Ա.

    /*
    FltGetFileNameInformation cannot get file name information if the TopLevelIrp field of the current thread is not NULL,
    because the resulting file system recursion could cause deadlocks or stack overflows. (For more information about this issue, see IoGetTopLevelIrp.)
    FltGetFileNameInformation cannot get file name information in the paging I/O path.
    FltGetFileNameInformation cannot get file name information in the post-close path.
    FltGetFileNameInformation cannot get the short name of a file in the pre-create path.
    */
    if (FlagOn(Cbd->Iopb->IrpFlags, IRP_PAGING_IO) ||
        FlagOn(Cbd->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO) ||
        IoGetTopLevelIrp()) //IRP_NOCACHE
    {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%wZ, IrpFlags:0x%#x",
              &FltObjects->FileObject->FileName, Cbd->Iopb->IrpFlags);
        FreeUnicodeString(usFullPath);
        return Status;
    }

    if (FlagOn(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {
        ClearFlag(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY);
        Status = FltGetFileNameInformation(Cbd, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY, &pfni);
        if (!NT_SUCCESS(Status)) {
            //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�ļ�/Ŀ¼:%wZ��status:0x%#x", &FltObjects->FileObject->FileName, Status);          
        }
        SetFlag(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY);
    } else {
        Status = FltGetFileNameInformation(Cbd, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pfni);
        if (!NT_SUCCESS(Status)) {
            //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�ļ�/Ŀ¼:%wZ��status:0x%#x", &FltObjects->FileObject->FileName, Status);
        }
    }

    if (NT_SUCCESS(Status)) {
        RtlCopyUnicodeString(usFullPath, &pfni->Name);
        FltReleaseFileNameInformation(pfni);
        return Status;
    }

    if (!NT_SUCCESS(Status)) {
        UNICODE_STRING  VolumeName = {0};
        ULONG  BufferSizeNeeded;

        Status = FltGetVolumeName(FltObjects->Volume, usFullPath, &BufferSizeNeeded);
        if (!NT_SUCCESS(Status)) {
            KdPrint(("FltGetVolumeName fail with 0x%0x!\r\n", Status));
            FreeUnicodeString(usFullPath);
            return Status;
        }

        if (NULL != FltObjects->FileObject->RelatedFileObject) {
            RtlAppendUnicodeStringToString(usFullPath, &FltObjects->FileObject->RelatedFileObject->FileName);
            RtlAppendUnicodeToString(usFullPath, L"\\");
        }

        Status = RtlAppendUnicodeStringToString(usFullPath, &FltObjects->FileObject->FileName);
        if (!NT_SUCCESS(Status)) {
            FreeUnicodeString(usFullPath);
            return Status;
        }

        return Status;;
    }

    return Status;
}


#if (NTDDI_VERSION < NTDDI_VISTA)
NTSTATUS FltQueryDirectoryFile(_In_ PFLT_INSTANCE Instance,
                               _In_ PFILE_OBJECT FileObject,
                               _Out_writes_bytes_(Length) PVOID FileInformationBuffer,
                               _In_ ULONG Length,
                               _In_ FILE_INFORMATION_CLASS FileInformationClass,
                               _In_ BOOLEAN ReturnSingleEntry,
                               _In_opt_ PUNICODE_STRING FileName,
                               _In_ BOOLEAN RestartScan,
                               _Out_opt_ PULONG LengthReturned
)
/*++
Routine Description:
    ΪXP��������FltQueryDirectoryFile
    ���Ҫ��XP�����У�����XP�±��룬������������ʧ�ܡ�
    This function is like ZwQueryDirectoryFile for filters
    ����Ϊ��ZwQueryDirectoryFile_LongNameɶ�ĽϺá�
    ע�⣺FltQueryDirectoryFile��Vista���У�ZwQueryDirectoryFile��Xp���С�
Arguments:
    Instance - Supplies the Instance initiating this IO.
    FileObject - Supplies the file object about which the requested information should be changed.
    FileInformation - Supplies a buffer containing the information which should be changed on the file.
    Length - Supplies the length, in bytes, of the FileInformation buffer.
    FileInformationClass - Specifies the type of information which should be changed about the file.
    ReturnSingleEntry - If this parameter is TRUE, FltQueryDirectoryFile returns only the first entry that is found.
    FileName - An optional pointer to a caller-allocated Unicode string containing the name of a file (or multiple files, if wildcards are used)  within the directory specified by FileHandle.
               This parameter is optional and can be NULL.
    RestartScan - Set to TRUE if the scan is to start at the first entry in the directory. Set to FALSE if resuming the scan from a previous call.
Return Value:
    The Status returned is the final completion Status of the operation.
--*/
{
    PFLT_CALLBACK_DATA data;
    NTSTATUS Status;

    PAGED_CODE();

    //  Customized FltQueryDirectoryFile if it is not exported from FltMgr.
    Status = FltAllocateCallbackData(Instance, FileObject, &data);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    data->Iopb->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
    data->Iopb->MinorFunction = IRP_MN_QUERY_DIRECTORY;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length = Length;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName = FileName;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass = FileInformationClass;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileIndex = 0;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = FileInformationBuffer;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress = NULL;

    if (RestartScan) {
        data->Iopb->OperationFlags |= SL_RESTART_SCAN;
    }
    if (ReturnSingleEntry) {
        data->Iopb->OperationFlags |= SL_RETURN_SINGLE_ENTRY;
    }

    FltPerformSynchronousIo(data);//  Perform a synchronous operation.

    Status = data->IoStatus.Status;

    if (ARGUMENT_PRESENT(LengthReturned) && NT_SUCCESS(Status)) {
        *LengthReturned = (ULONG)data->IoStatus.Information;
    }

    FltFreeCallbackData(data);

    return Status;
}
#endif


#if (NTDDI_VERSION < NTDDI_WIN7)
//NTKERNELAPI
NTSTATUS IoReplaceFileObjectName(_In_ PFILE_OBJECT FileObject,
                                 _In_reads_bytes_(FileNameLength) PWSTR NewFileName,
                                 _In_ USHORT FileNameLength
)
/*++
Routine Description:
    This routine is used to replace a file object's name with a provided name.
    This should only be called if IoReplaceFileObjectName is not on the system.
    If this function is used and verifier is enabled the filter will fail to unload due to a false positive on the leaked pool test.
Arguments:
    FileObject - Pointer to file object whose name is to be replaced.
    NewFileName - Pointer to buffer containing the new name.
    FileNameLength - Length of the new name in bytes.
Return Value:
    STATUS_INSUFFICIENT_RESOURCES - No memory to allocate the new buffer.
    STATUS_SUCCESS otherwise.
--*/
{
    PWSTR buffer;
    PUNICODE_STRING fileName;
    USHORT newMaxLength;

    PAGED_CODE();

    fileName = &FileObject->FileName;

    // If the new name fits inside the current buffer we simply copy it over instead of allocating a new buffer (and keep the MaximumLength value the same).
    if (FileNameLength <= fileName->MaximumLength) {
        goto CopyAndReturn;
    }

    // Use an optimal buffer size
    newMaxLength = FileNameLength;
    buffer = ExAllocatePoolWithTag(NonPagedPool, newMaxLength, TAG);//PagedPool
    if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (fileName->Buffer != NULL) {
        ExFreePool(fileName->Buffer);
    }

    fileName->Buffer = buffer;
    fileName->MaximumLength = newMaxLength;

CopyAndReturn:

    fileName->Length = FileNameLength;
    RtlZeroMemory(fileName->Buffer, fileName->MaximumLength);
    RtlCopyMemory(fileName->Buffer, NewFileName, FileNameLength);

    return STATUS_SUCCESS;
}
#endif


VOID PrintVolume(__in PCFLT_RELATED_OBJECTS FltObjects)
/*
���ܣ���ӡ���صĶ������Ϣ��

�˺���һ�㽨������InstanceSetup�С�
*/
{
    NTSTATUS Status;
    PVOID Buffer;
    ULONG BufferSizeNeeded;
    UNICODE_STRING Volume;

    Status = FltGetVolumeName(FltObjects->Volume, NULL, &BufferSizeNeeded);
    if (Status != STATUS_BUFFER_TOO_SMALL) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return;
    }

    Buffer = ExAllocatePoolWithTag(PagedPool, (SIZE_T)BufferSizeNeeded + 2, TAG);
    if (Buffer == NULL) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "%s", "�����ڴ�ʧ��");
        return;
    }
    RtlZeroMemory(Buffer, (size_t)BufferSizeNeeded + 2);

    Volume.Buffer = (PWCH)Buffer;
    Volume.Length = (USHORT)BufferSizeNeeded;
    Volume.MaximumLength = (USHORT)BufferSizeNeeded + 2;
    Status = FltGetVolumeName(FltObjects->Volume, &Volume, &BufferSizeNeeded);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
    } else {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_INFO_LEVEL, "��Ϣ��attached device:%wZ", &Volume);
    }

    ExFreePoolWithTag(Buffer, TAG);
}


NTSTATUS ZwGetDosFileName(_Inout_ PFLT_CALLBACK_DATA Data,
                          _In_ PCFLT_RELATED_OBJECTS FltObjects,
                          OUT PUNICODE_STRING DosFileName
)
/*
���ܣ���ȡ�ļ���DOS����
��Ҫ����Create��ǰ���������Ϊ����Ĳ����϶��Ǵ��Լ����ֵ��������л�ȡ�ġ�

�����кö�û�о��������豸�Ĳ�����

������������ܺ͹��ܶ�����FltGetDosFileName�á�
FltGetDosFileName������������Լ�д�ģ��õ��˾������ģ��������ﲻ�����ˡ�

IoVolumeDeviceToDosName��IoQueryFileDosDeviceName��ȫ����Ϊ���Ѿ������ˣ������ļ�ȴ��һ�����򿪡�
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PFLT_FILE_NAME_INFORMATION nameInfo;
    PDEVICE_OBJECT DiskDeviceObject = NULL;
    UNICODE_STRING VolumeName;

    Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(Status)) {
        //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�ļ�/Ŀ¼:%wZ��status:0x%#x", &FltObjects->FileObject->FileName, Status);//��Ϣ̫�ࡣ
        return Status;//�����з���STATUS_OBJECT_PATH_NOT_FOUND
    }

    Status = FltParseFileNameInformation(nameInfo);
    ASSERT(NT_SUCCESS(Status));

    Status = FltGetDiskDeviceObject(FltObjects->Volume, &DiskDeviceObject);
    if (NT_SUCCESS(Status)) {
        Status = IoVolumeDeviceToDosName(DiskDeviceObject, &VolumeName);//������ð�š�
        if (NT_SUCCESS(Status)) {
            DosFileName->MaximumLength = VolumeName.MaximumLength + nameInfo->Name.MaximumLength;
            DosFileName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, DosFileName->MaximumLength, TAG);
            ASSERT(NULL != DosFileName->Buffer);
            DosFileName->Length = 0;
            RtlZeroMemory(DosFileName->Buffer, DosFileName->MaximumLength);

            RtlCopyUnicodeString(DosFileName, &VolumeName);
            //Status = RtlAppendUnicodeToString(DosFileName, L":");
            //ASSERT(NT_SUCCESS(Status));
            Status = RtlUnicodeStringCbCatN(DosFileName, &nameInfo->ParentDir, nameInfo->ParentDir.Length); //ǰ����\. 
            ASSERT(NT_SUCCESS(Status));
            Status = RtlUnicodeStringCbCatN(DosFileName, &nameInfo->FinalComponent, nameInfo->FinalComponent.Length);
            ASSERT(NT_SUCCESS(Status));
        } else {
            PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_WARNING_LEVEL, "Status:%#X, FileName:%wZ",
                    Status, &FltObjects->FileObject->FileName);
        }
    } else {//������Ĳ��١�
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_WARNING_LEVEL, "Status:%#X, FileName:%wZ",
                Status, &FltObjects->FileObject->FileName);//STATUS_FLT_NO_DEVICE_OBJECT
    }

    FltReleaseFileNameInformation(nameInfo);

    return Status;
}


NTSTATUS ZwCreateHardLink(__in PUNICODE_STRING HardLinkFileName, __in PUNICODE_STRING  ExistingFileName)
/*
���ܣ�����Ӳ���ӡ�
ע�⣺1.��ͬһ����
      2.ExistingFileNameҪ����
      3.ExistingFileName���ļ�
      4.ExistingFileName�����Ӹ������ܳ���1023.
      5.

made by correy
made at 2015.09.27
homepage:https://correy.webs.com
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ob;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    HANDLE FileHandle;
    PFILE_LINK_INFORMATION FILELINKINFORMATION = NULL;
    ULONG  Length = 0;

    /*
    һЩ�����ļ�顣
    */

    InitializeObjectAttributes(&ob, ExistingFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenFile(&FileHandle,
                        FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                        &ob,
                        &IoStatusBlock,
                        FILE_SHARE_VALID_FLAGS,
                        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT);//FILE_NON_DIRECTORY_FILE
    if (!NT_SUCCESS(Status)) {
        KdPrint(("ZwOpenFile fail %d\n", Status));
        return Status;
    }

    //���������ڴ棬��ΪFILELINKINFORMATION->FileName�ĺ��������ܵ��ڴ档
    Length = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) + HardLinkFileName->Length;//sizeof(FILE_RENAME_INFORMATION)        
    FILELINKINFORMATION = (PFILE_LINK_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
    if (FILELINKINFORMATION == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        return Status;
    }
    RtlZeroMemory(FILELINKINFORMATION, Length);

    FILELINKINFORMATION->FileNameLength = HardLinkFileName->Length;
    RtlCopyMemory(FILELINKINFORMATION->FileName, HardLinkFileName->Buffer, HardLinkFileName->Length);

    Status = ZwSetInformationFile(FileHandle, &IoStatusBlock, FILELINKINFORMATION, Length, FileLinkInformation);
    if (!NT_SUCCESS(Status)) {
        KdPrint(("ZwSetInformationFile fail %d\n", Status));
    }

    ExFreePoolWithTag(FILELINKINFORMATION, TAG);
    ZwClose(FileHandle);

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS EnumerateRegisteredFilters()
/*
IoEnumerateRegisteredFiltersList enumerates only file system filter drivers (also called "legacy filters").
It does not enumerate minifilters.
To enumerate both minifilters and legacy filters, or only minifilters, call FltEnumerateFilterInformation.

�˴�����Windows 7�ϲ��Գɹ���
����֮������ָ����

made by correy
made at 2014.07.01
homepage:http://correy.webs.com
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PDRIVER_OBJECT * DriverObjectList = 0;//*
    ULONG DriverObjectListSize = 0;
    ULONG ActualNumberDriverObjects = 0;
    ULONG i = 0;

    //XP�µ��ô˺���û�з�Ӧ�����Ǹ�������������ֵ������ԭ�������ӡ�
    Status = IoEnumerateRegisteredFiltersList(DriverObjectList, DriverObjectListSize, &ActualNumberDriverObjects);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return Status;
        }
    }

    //XP�������СΪ0���ڴ澹Ȼ�ɹ������һ����Զ�д��
    DriverObjectListSize = ActualNumberDriverObjects * sizeof(DRIVER_OBJECT);
    DriverObjectList = (PDRIVER_OBJECT *)ExAllocatePoolWithTag(NonPagedPool, DriverObjectListSize, TAG);
    if (DriverObjectList == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    RtlZeroMemory(DriverObjectList, DriverObjectListSize);

    //XP�µ��ô˺�����Ȼû�з�Ӧ�����Ǹ�������������ֵ������ԭ�������ӡ�
    Status = IoEnumerateRegisteredFiltersList(DriverObjectList, DriverObjectListSize, &ActualNumberDriverObjects);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    for (i = 0; i < ActualNumberDriverObjects; i++) {
        DbgPrint("DriverName:%wZ\n", &DriverObjectList[i]->DriverName);
        ObDereferenceObject(DriverObjectList[i]);
    }

    ExFreePoolWithTag(DriverObjectList, TAG);

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
�ļ���:EnumerateFilters.C

΢������ʹ��:IoEnumerateRegisteredFiltersList.

����:enumerates all registered minifilter drivers in the system����һЩ��Ϣ����ʾ.
Ŀ��:ʾ��һЩminifilter��һЩö�ٺ������÷�,���,����.

����Ҫ����fltMgr.lib.
���صķ�ʽ����һ�������(nt����).

�ο�����:
http://hi.baidu.com/kernelkit/item/95dab957bf115711aaf6d743
http://www.inreverse.net/?p=1334
http://blogs.msdn.com/b/alexcarp/archive/2009/08/11/issuing-io-in-minifilters-part-1-fltcreatefile.aspx
http://blogs.msdn.com/b/alexcarp/archive/2009/09/01/issuing-io-in-minifilters-part-2-flt-vs-zw.aspx
http://blogs.msdn.com/b/alexcarp/archive/2009/06/16/filter-manager-concepts-part-3-flt-filter.aspx
http://blogs.msdn.com/b/alexcarp/archive/2009/06/24/filter-manager-concepts-part-4-flt-instance.aspx
��.

����֮��,����ָ��.
made by correy
made at 2013.10.23

���˸о�FltEnumerateInstances��FltEnumerateVolumes���.
������ǰ���ܻ�ȡ���е�minifilter�����е�ʵ������Ϣ,����ֻ��ȡĳ��minifilter�����еľ��豸����Ϣ.
������ת������ϵ�ĺ���.

��ʼ��Ϊ:FltEnumerateVolumes�ǻ�ȡ��һ��PFLT_FILTER���˵ľ��豸�Ķ���,����ȫ���Ĵ����ϵľ�.
��������:��ȡ���ؼ�����ϵĿ��õľ�.һ���ǻ�ȡ������:
1.��������û�й���.
2.������������������ľ��豸.
3.����ӳ����̷�.
4.subst����������������.
5.����û�в���.
���������ȱ���ǵ�һ������,���һ�������0,���˽�����ȥ���������.
������minifilter���������������������.
*/


void PrintFilterFullInformation(PFLT_FILTER pf)
{
    //��һ��˼·��ʹ��:FltEnumerateFilterInformation

    NTSTATUS Status = STATUS_SUCCESS;
    PVOID  Buffer = 0;
    ULONG  BufferSize = 0;
    ULONG  BytesReturned = 0;
    PFILTER_FULL_INFORMATION pfi = 0;
    UNICODE_STRING FilterName;

    Status = FltGetFilterInformation(pf, FilterFullInformation, Buffer, BufferSize, &BytesReturned);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return;
        }
    }

    BufferSize = sizeof(PFLT_FILTER) * BytesReturned * 2;//������һ��.
    Buffer = (PFLT_FILTER *)ExAllocatePoolWithTag(NonPagedPool, BufferSize, TAG);
    if (Buffer == NULL) {
        return;
    }
    RtlZeroMemory(Buffer, BufferSize);

    Status = FltGetFilterInformation(pf, FilterFullInformation, Buffer, BufferSize, &BytesReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, TAG);
        return;
    }

    pfi = (PFILTER_FULL_INFORMATION)Buffer;

    FilterName.Buffer = pfi->FilterNameBuffer;
    FilterName.Length = pfi->FilterNameLength;
    FilterName.MaximumLength = pfi->FilterNameLength;//���ټ�2.

    //DbgPrint("FrameID:%d\n", pfi->FrameID);
    //DbgPrint("NumberOfInstances:%d\n", pfi->NumberOfInstances);
    DbgPrint("FilterName:%wZ\n", &FilterName);

    /*
    ��ӡ����������:
    FrameID:0
    NumberOfInstances:5
    FilterName:TFsFlt
    FrameID:0
    NumberOfInstances:6
    FilterName:QQSysMonX64
    FrameID:0
    NumberOfInstances:1
    FilterName:luafv ע��:΢���LUA�ļ����⻯ɸѡ����������.
    */

    ExFreePoolWithTag(Buffer, TAG);
}


void PrintVolumeStandardInformation(PFLT_VOLUME pv)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID  Buffer = 0;
    ULONG  BufferSize = 0;
    ULONG  BytesReturned = 0;
    PFILTER_VOLUME_STANDARD_INFORMATION pvsi = 0;
    UNICODE_STRING VolumeName;

    Status = FltGetVolumeInformation(pv, FilterVolumeStandardInformation, Buffer, BufferSize, &BytesReturned);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return;
        }
    }

    BufferSize = sizeof(PFLT_FILTER) * BytesReturned * 2;//������һ��.
    Buffer = (PFLT_FILTER *)ExAllocatePoolWithTag(NonPagedPool, BufferSize, TAG);
    if (Buffer == NULL) {
        return;
    }
    RtlZeroMemory(Buffer, BufferSize);

    Status = FltGetVolumeInformation(pv, FilterVolumeStandardInformation, Buffer, BufferSize, &BytesReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, TAG);
        return;
    }

    pvsi = (PFILTER_VOLUME_STANDARD_INFORMATION)Buffer;

    VolumeName.Buffer = pvsi->FilterVolumeName;
    VolumeName.Length = pvsi->FilterVolumeNameLength;
    VolumeName.MaximumLength = pvsi->FilterVolumeNameLength;//���ټ�2.

    //DbgPrint("Flags:%d\n", pvsi->Flags);
    //DbgPrint("FrameID:%d\n", pvsi->FrameID);
    DbgPrint("VolumeName:%wZ\n", &VolumeName);

    switch (pvsi->FileSystemType) {
    case FLT_FSTYPE_UNKNOWN:
        DbgPrint("FileSystemType :%ls\n", L"Unknown file system type.");
        break;
    case FLT_FSTYPE_RAW:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\RAW.");
        break;
    case FLT_FSTYPE_NTFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Ntfs.");
        break;
    case FLT_FSTYPE_FAT:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Fat.");
        break;
    case FLT_FSTYPE_CDFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Cdfs.");
        break;
    case FLT_FSTYPE_UDFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Udfs.");
        break;
    case FLT_FSTYPE_LANMAN:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\MRxSmb.");
        break;
    case FLT_FSTYPE_WEBDAV:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\MRxDav.");
        break;
    case FLT_FSTYPE_RDPDR:
        DbgPrint("FileSystemType :%ls\n", L"\\Driver\\rdpdr.");
        break;
    case FLT_FSTYPE_NFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\NfsRdr.");
        break;
    case FLT_FSTYPE_MS_NETWARE:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\nwrdr.");
        break;
    case FLT_FSTYPE_NETWARE:
        DbgPrint("FileSystemType :%ls\n", L"Novell NetWare redirector.");
        break;
    case FLT_FSTYPE_BSUDF:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\BsUDF.");
        break;
    case FLT_FSTYPE_MUP:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Mup.");
        break;
    case FLT_FSTYPE_RSFX:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\RsFxDrv.");
        break;
    case FLT_FSTYPE_ROXIO_UDF1:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\cdudf_xp.");
        break;
    case FLT_FSTYPE_ROXIO_UDF2:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\UdfReadr_xp.");
        break;
    case FLT_FSTYPE_ROXIO_UDF3:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\DVDVRRdr_xp.");
        break;
    case FLT_FSTYPE_TACIT:
        DbgPrint("FileSystemType :%ls\n", L"\\Device\\TCFSPSE.");
        break;
    case FLT_FSTYPE_FS_REC:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Fs_rec.");
        break;
    case FLT_FSTYPE_INCD:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\InCDfs.");
        break;
    case FLT_FSTYPE_INCD_FAT:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\InCDFat.");
        break;
    case FLT_FSTYPE_EXFAT:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\exfat.");
        break;
    case FLT_FSTYPE_PSFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\psfs.");
        break;
    case FLT_FSTYPE_GPFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\gpfs.");
        break;
    case FLT_FSTYPE_NPFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\npfs.");
        break;
    case FLT_FSTYPE_MSFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\msfs.");
        break;
    case FLT_FSTYPE_CSVFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\csvfs.");
        break;
    case FLT_FSTYPE_REFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\refs.");
        break;
    case FLT_FSTYPE_OPENAFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\AFSRedirector.");
        break;
    default:
        DbgPrint("FileSystemType :%ls\n", L"��������!");
        break;
    }

    //����ҲҪ��FltObjectDereference���ͷ�һ��?
    FltObjectDereference(pv);

    ExFreePoolWithTag(Buffer, TAG);
}


void EnumerateInstances(PFLT_FILTER pf)
{
    //FltEnumerateInstances
    //FltGetInstanceInformation �����ȡ��ȫ������,���Է���ʹ��.
    //FltEnumerateInstanceInformationByFilter �����ȡ��ȫ������,���Է���ʹ��.
    //FltEnumerateInstanceInformationByVolume �����ȡ��ȫ������,���Է���ʹ��.

    NTSTATUS Status = STATUS_SUCCESS;
    PFLT_INSTANCE * InstanceList = 0;
    ULONG  InstanceListSize = 0;
    ULONG  NumberInstancesReturned = 0;
    ULONG i;

    Status = FltEnumerateInstances(0, pf, InstanceList, InstanceListSize, &NumberInstancesReturned);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return;
        }
    }

    InstanceListSize = sizeof(PFLT_INSTANCE) * NumberInstancesReturned * 2;//������һ��.
    InstanceList = (PFLT_INSTANCE *)ExAllocatePoolWithTag(NonPagedPool, InstanceListSize, TAG);
    if (InstanceList == NULL) {
        return;
    }
    RtlZeroMemory(InstanceList, InstanceListSize);

    Status = FltEnumerateInstances(0, pf, InstanceList, InstanceListSize, &NumberInstancesReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(InstanceList, TAG);
        return;
    }

    for (i = 0; i < NumberInstancesReturned; i++) {
        //��ӡÿ��ʵ������Ϣ.
        //���ź;��豸��һ����,ת��Ϊ���豸�ٴ�ӡ,����Ͳ���ӡ��ϸ��Ϣ��,ֻ��ӡʵ���ĵ�ַ.
        DbgPrint("PFLT_FILTER:%p\tInstances:%p\n", pf, InstanceList[i]);

        FltObjectDereference(InstanceList[i]);
    }

    //����ҲҪ��FltObjectDereference���ͷ�һ��?
    FltObjectDereference(pf);

    ExFreePoolWithTag(InstanceList, TAG);
}


void EnumerateVolumes(PFLT_FILTER pf)
{
    //FltEnumerateVolumes�����ȡȫ��,Ҫö��.
    //FltGetVolumeInformation
    //FltEnumerateVolumeInformation�������,�ǻ�ȡ������,Ҫѭ��.

    NTSTATUS Status = STATUS_SUCCESS;
    PFLT_VOLUME * VolumeList = 0;
    ULONG  VolumeListSize = 0;
    ULONG  NumberVolumesReturned = 0;
    ULONG i;

    Status = FltEnumerateVolumes(pf, VolumeList, VolumeListSize, &NumberVolumesReturned);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return;
        }
    }

    VolumeListSize = sizeof(PFLT_VOLUME) * NumberVolumesReturned * 2;//������һ��.

    VolumeList = (PFLT_VOLUME *)ExAllocatePoolWithTag(NonPagedPool, VolumeListSize, TAG);
    if (VolumeList == NULL) {
        return;
    }
    RtlZeroMemory(VolumeList, VolumeListSize);

    Status = FltEnumerateVolumes(pf, VolumeList, VolumeListSize, &NumberVolumesReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(VolumeList, TAG);
        return;
    }

    for (i = 0; i < NumberVolumesReturned; i++) {
        //��ӡÿ�����豸����Ϣ.
        PrintVolumeStandardInformation(VolumeList[i]);

        FltObjectDereference(VolumeList[i]);
    }

    //����ҲҪ��FltObjectDereference���ͷ�һ��?
    FltObjectDereference(pf);

    ExFreePoolWithTag(VolumeList, TAG);
}


NTSTATUS EnumerateFilters()
{
    NTSTATUS Status = STATUS_SUCCESS;
    PFLT_FILTER * FilterList;
    ULONG FilterListSize = 0;
    ULONG NumberFiltersReturned = 0;
    ULONG i;

    //Because filters can register at any time, two calls to FltEnumerateFilters are not guaranteed to return the same result.
    //ȷ�����ε���FltEnumerateFilters�ڼ䲻Ҫ���ػ���ж��minifilter.����ʹ��rundown����.
    Status = FltEnumerateFilters(0, FilterListSize, &NumberFiltersReturned);
    if (!NT_SUCCESS(Status)) //#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
    {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return Status;
        }
    }

    //����ÿ�γɹ��ĵ���֮�󶼵���:VOID FltObjectDereference(_Inout_  PVOID FltObject);

    FilterListSize = sizeof(PFLT_FILTER) * NumberFiltersReturned * 2;//������һ��.
    FilterList = (PFLT_FILTER *)ExAllocatePoolWithTag(NonPagedPool, FilterListSize, TAG);
    if (FilterList == NULL) {
        return Status;
    }
    RtlZeroMemory(FilterList, FilterListSize);

    Status = FltEnumerateFilters(FilterList, FilterListSize, &NumberFiltersReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(FilterList, TAG);
        return Status;
    }

    //ж�������Ѿ�ע���minifilter.�����ϱ�Ĩȥδ�����Ľṹ��.������ʱע�͵�.
    //for (i = 0;i < NumberFiltersReturned;i++)
    //{
    //    FltUnregisterFilter(FilterList[i]);//�е���������Զֹͣ������.
    //}

    /*
    ����������о�һЩminifilter����Ϣ
    ����ÿ��minifilter���˵�ÿ�����豸����Ϣ.

    PFLT_FILTER�Ǹ�Ϊ���������ݽṹ,�����汾�Ľṹ��һ.

    0: kd> vertarget
    Windows 7 Kernel Version 7601 (Service Pack 1) MP (2 procs) Free x64
    Built by: 7601.18229.amd64fre.win7sp1_gdr.130801-1533
    Machine Name:
    Kernel base = 0xfffff800`0185f000 PsLoadedModuleList = 0xfffff800`01aa26d0
    Debug session time: Wed Oct 23 16:25:06.039 2013 (UTC + 8:00)
    System Uptime: 0 days 0:04:08.664
    0: kd> dt _FLT_FILTER fffffa80`04306c60
    fltmgr!_FLT_FILTER
    +0x000 Base             : _FLT_OBJECT
    +0x020 Frame            : 0xfffffa80`03f30630 _FLTP_FRAME
    +0x028 Name             : _UNICODE_STRING "TFsFlt"
    +0x038 DefaultAltitude  : _UNICODE_STRING "389700"
    +0x048 Flags            : 2 ( FLTFL_FILTERING_INITIATED )
    +0x050 DriverObject     : 0xfffffa80`042fde70 _DRIVER_OBJECT
    +0x058 InstanceList     : _FLT_RESOURCE_LIST_HEAD
    +0x0d8 VerifierExtension : (null)
    +0x0e0 VerifiedFiltersLink : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
    +0x0f0 FilterUnload     : 0xfffff880`0245f320     long  +0
    +0x0f8 InstanceSetup    : 0xfffff880`0248d0ec     long  +0
    +0x100 InstanceQueryTeardown : 0xfffff880`0248d118     long  +0
    +0x108 InstanceTeardownStart : (null)
    +0x110 InstanceTeardownComplete : 0xfffff880`0248d138     void  +0
    +0x118 SupportedContextsListHead : 0xfffffa80`04306890 _ALLOCATE_CONTEXT_HEADER
    +0x120 SupportedContexts : [6] (null)
    +0x150 PreVolumeMount   : (null)
    +0x158 PostVolumeMount  : (null)
    +0x160 GenerateFileName : (null)
    +0x168 NormalizeNameComponent : (null)
    +0x170 NormalizeNameComponentEx : (null)
    +0x178 NormalizeContextCleanup : (null)
    +0x180 KtmNotification  : (null)
    +0x188 Operations       : 0xfffffa80`04306ef0 _FLT_OPERATION_REGISTRATION
    +0x190 OldDriverUnload  : (null)
    +0x198 ActiveOpens      : _FLT_MUTEX_LIST_HEAD
    +0x1e8 ConnectionList   : _FLT_MUTEX_LIST_HEAD
    +0x238 PortList         : _FLT_MUTEX_LIST_HEAD
    +0x288 PortLock         : _EX_PUSH_LOCK

    �ٸ��������ṹ:
    1: kd> dt _FLT_INSTANCE
    fltmgr!_FLT_INSTANCE
    +0x000 Base             : _FLT_OBJECT
    +0x020 OperationRundownRef : Ptr64 _EX_RUNDOWN_REF_CACHE_AWARE
    +0x028 Volume           : Ptr64 _FLT_VOLUME
    +0x030 Filter           : Ptr64 _FLT_FILTER
    +0x038 Flags            : _FLT_INSTANCE_FLAGS
    +0x040 Altitude         : _UNICODE_STRING
    +0x050 Name             : _UNICODE_STRING
    +0x060 FilterLink       : _LIST_ENTRY
    +0x070 ContextLock      : _EX_PUSH_LOCK
    +0x078 Context          : Ptr64 _CONTEXT_NODE
    +0x080 TransactionContexts : _CONTEXT_LIST_CTRL
    +0x088 TrackCompletionNodes : Ptr64 _TRACK_COMPLETION_NODES
    +0x090 CallbackNodes    : [50] Ptr64 _CALLBACK_NODE
    1: kd> dt _FLT_VOLUME
    fltmgr!_FLT_VOLUME
    +0x000 Base             : _FLT_OBJECT
    +0x020 Flags            : _FLT_VOLUME_FLAGS
    +0x024 FileSystemType   : _FLT_FILESYSTEM_TYPE
    +0x028 DeviceObject     : Ptr64 _DEVICE_OBJECT
    +0x030 DiskDeviceObject : Ptr64 _DEVICE_OBJECT
    +0x038 FrameZeroVolume  : Ptr64 _FLT_VOLUME
    +0x040 VolumeInNextFrame : Ptr64 _FLT_VOLUME
    +0x048 Frame            : Ptr64 _FLTP_FRAME
    +0x050 DeviceName       : _UNICODE_STRING
    +0x060 GuidName         : _UNICODE_STRING
    +0x070 CDODeviceName    : _UNICODE_STRING
    +0x080 CDODriverName    : _UNICODE_STRING
    +0x090 InstanceList     : _FLT_RESOURCE_LIST_HEAD
    +0x110 Callbacks        : _CALLBACK_CTRL
    +0x4f8 ContextLock      : _EX_PUSH_LOCK
    +0x500 VolumeContexts   : _CONTEXT_LIST_CTRL
    +0x508 StreamListCtrls  : _FLT_RESOURCE_LIST_HEAD
    +0x588 FileListCtrls    : _FLT_RESOURCE_LIST_HEAD
    +0x608 NameCacheCtrl    : _NAME_CACHE_VOLUME_CTRL
    +0x6b8 MountNotifyLock  : _ERESOURCE
    +0x720 TargetedOpenActiveCount : Int4B
    +0x728 TxVolContextListLock : _EX_PUSH_LOCK
    +0x730 TxVolContexts    : _TREE_ROOT

    ��������ʹ��:FltEnumerateFilterInformation����FltGetFilterInformation��ȡ������Ϣ.
    */

    //��ӡÿ����������Ϣ,����ѡ��FilterFullInformation����.
    for (i = 0; i < NumberFiltersReturned; i++) {
        PrintFilterFullInformation(FilterList[i]);//��ӡϵͳ�����е�minifilter ����.
        EnumerateInstances(FilterList[i]);//ö��ÿ��minifilter������ÿ�������豸��ʵ��,������Ի�ȡ�������Ϣ.
        EnumerateVolumes(FilterList[i]);//ö��ÿ��minifilter������ÿ�����豸����Ϣ,������Ի�ȡ�������Ϣ,��ʵ������Ĳ��.

        DbgPrint("\n\n");
    }

    /*
    FltEnumerateFilters adds a rundown reference to each of the opaque filter pointers returned in the array that the FilterList parameter points to.
    When these pointers are no longer needed, the caller must release them by calling FltObjectDereference on each one.
    Thus every successful call to FltEnumerateFilters must be matched by a subsequent call to FltObjectDereference for each returned filter pointer.
    */
    for (i = 0; i < NumberFiltersReturned; i++) {
        FltObjectDereference(FilterList[i]);
    }

    ExFreePoolWithTag(FilterList, TAG);

    return Status;
}


/*
Ч������:
0: kd> g
FilterName:TFsFlt
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA8004432C60
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA8004346C60
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA80047D3C60
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA80047B9C60
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA80040DF7F0
VolumeName:\Device\Mup
FileSystemType :\FileSystem\Mup.
VolumeName:\Device\HarddiskVolume1
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume2
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume5
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume3
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume4
FileSystemType :\FileSystem\Ntfs.


FilterName:QQSysMonX64
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004A9A760
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004A9D760
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004AA0C50
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004AA0170
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004AA34F0
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004AA4C50
VolumeName:\Device\Mup
FileSystemType :\FileSystem\Mup.
VolumeName:\Device\HarddiskVolume1
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume2
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume5
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume3
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume4
FileSystemType :\FileSystem\Ntfs.


FilterName:luafv
PFLT_FILTER:FFFFFA8004A8A010	Instances:FFFFFA8004A8C010
VolumeName:\Device\Mup
FileSystemType :\FileSystem\Mup.
VolumeName:\Device\HarddiskVolume1
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume2
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume5
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume3
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume4
FileSystemType :\FileSystem\Ntfs.

��֤һ��:
0: kd> !fltkd.filters

Filter List: fffffa8003e690c0 "Frame 0"
   FLT_FILTER: fffffa800433e010 "TFsFlt" "389700"
      FLT_INSTANCE: fffffa8004432c60 "TFsFlt Instance" "389700"
      FLT_INSTANCE: fffffa8004346c60 "TFsFlt Instance" "389700"
      FLT_INSTANCE: fffffa80047d3c60 "TFsFlt Instance" "389700"
      FLT_INSTANCE: fffffa80047b9c60 "TFsFlt Instance" "389700"
      FLT_INSTANCE: fffffa80040df7f0 "TFsFlt Instance" "389700"
   FLT_FILTER: fffffa8004a8b160 "QQSysMonX64" "327125"
      FLT_INSTANCE: fffffa8004a9a760 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004a9d760 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004aa0c50 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004aa0170 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004aa34f0 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004aa4c50 "QQSysMonx64 Instance" "327125"
   FLT_FILTER: fffffa8004a8a010 "luafv" "135000"
      FLT_INSTANCE: fffffa8004a8c010 "luafv" "135000"

0: kd> !fltkd.instance fffffa8004432c60

FLT_INSTANCE: fffffa8004432c60 "TFsFlt Instance" "389700"
   FLT_OBJECT: fffffa8004432c60  [01000000] Instance
      RundownRef               : 0x0000000000000000 (0)
      PointerCount             : 0x00000002
      PrimaryLink              : [fffffa8004a9d770-fffffa800404d108]
   OperationRundownRef      : fffffa80044310b0
Could not read field "Number" of fltmgr!_EX_RUNDOWN_REF_CACHE_AWARE from address: fffffa80044310b0
   Flags                    : [00000000]
   Volume                   : fffffa800404d010 "\Device\HarddiskVolume1"
   Filter                   : fffffa800433e010 "TFsFlt"
   TrackCompletionNodes     : fffffa8004432a20
   ContextLock              : (fffffa8004432cd0)
   Context                  : fffffa800433a770
   CallbackNodes            : (fffffa8004432cf0)
   VolumeLink               : [fffffa8004a9d770-fffffa800404d108]
   FilterLink               : [fffffa8004346cc0-fffffa800433e0d0]

*/


//////////////////////////////////////////////////////////////////////////////////////////////////


#define MAX_NTFS_METADATA_FILE 11


/*
���ժ�ԣ�filemon��
*/
CHAR * NtfsMetadataFileNames[] = {
    "$Mft",
    "$MftMirr",
    "$LogFile",
    "$Volume",
    "$AttrDef",
    "$Root",
    "$Bitmap",
    "$Boot",
    "$BadClus",
    "$Secure",
    "$UpCase",
    "$Extend"
};


void PrintNtfsMetadataFileName(_In_ PFLT_INSTANCE Instance, _In_ PFILE_OBJECT FileObject)
/*
���ܣ�ʶ��NTFS/REFS���ļ�ϵͳ��Ԫ���ݡ�

�����ǣ�ftl��ʵ�֣�����zw��ʵ�֡�

�ο���
1.filemon.c
2.Windows 8 Driver Samples\Metadata Manager File System Minifilter Driver
3.passThrough

ע���ھ��ʵ����/���ص�ʱ�����ѡ��
if (VolumeFilesystemType != FLT_FSTYPE_NTFS && VolumeFilesystemType != FLT_FSTYPE_FAT && VolumeFilesystemType != FLT_FSTYPE_REFS)
{
    Status = STATUS_NOT_SUPPORTED;
    ......
}

��ʵ:
1.filemon�ܾã����Ǻ��вο��ļ�ֵ��
2.Windows 8 Driver Samples\Metadata Manager File System Minifilter Driver����׸����win 10�Ϻö���Ϣ��û�����ص���������Procmon.exe����":\$"���Ƚ�.
3.������ȷ�ĺ������Լ�����Ļ����Լ�����

//��ʵ�������Ϊ���˵�������ժ�ԣ�\Windows 8 Driver Samples\Metadata Manager File System Minifilter Driver
FLT_ASSERT((!(Data->Iopb->TargetFileObject->FileName.Length == 0 && Data->Iopb->TargetFileObject->RelatedFileObject == NULL)) ||
            FlagOn(Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN));

made by correy
made at 2016/4/11
http://correy.webs.com
*/
{
    FILE_INTERNAL_INFORMATION fileInternalInfo;
    ULONG LengthReturned = 0;
    NTSTATUS Status = FltQueryInformationFile(Instance,
                                              FileObject,
                                              &fileInternalInfo,
                                              sizeof(fileInternalInfo),
                                              FileInternalInformation,
                                              &LengthReturned);
    if (NT_SUCCESS(Status)) {
        ULONGLONG mftIndex = fileInternalInfo.IndexNumber.QuadPart & ~0xF0000000;// Use the name in the metadata name index
        if (mftIndex <= MAX_NTFS_METADATA_FILE) {
            KdPrint(("NtfsMetadataFileName:%s.\r\n", NtfsMetadataFileNames[mftIndex]));
        }
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL IsFileExist(__inout PFLT_CALLBACK_DATA Data)
/*
����:�ж��ļ����ڲ���
ע�⣺����û�п��Ǳ�Ĵ�ʧ�ܵ������
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE FileHandle = NULL;
    OBJECT_ATTRIBUTES objAttributes = {0};
    IO_STATUS_BLOCK ioStatusBlock = {0};
    BOOL B = FALSE;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;

    if (IRP_MJ_CREATE != Data->Iopb->MajorFunction) {
        return B;//ֻ֧�����������
    }

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return B;
    }

    do {
        Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &NameInfo);
        if (!NT_SUCCESS(Status)) {//STATUS_OBJECT_PATH_NOT_FOUND
            //PrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            break;
        }

        Status = FltParseFileNameInformation(NameInfo);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        InitializeObjectAttributes(&objAttributes, &NameInfo->Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = FltCreateFile(NULL,
                               Data->Iopb->TargetInstance,//FltObjects->Instance,
                               &FileHandle,
                               FILE_GENERIC_READ | SYNCHRONIZE,
                               &objAttributes,
                               &ioStatusBlock,
                               0,
                               FILE_ATTRIBUTE_NORMAL,
                               FILE_SHARE_VALID_FLAGS,
                               FILE_OPEN,
                               FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                               NULL,
                               0,
                               IO_IGNORE_SHARE_ACCESS_CHECK);
        if (!NT_SUCCESS(Status)) {
            //PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            break;
        }

        B = TRUE;
    } while (FALSE);

    if (FileHandle) {
        Status = FltClose(FileHandle);//�Ͻ�ʹ��ZwClose��������Դй¶������������֤���»��⵽��
    }

    if (NameInfo) {
        FltReleaseFileNameInformation(NameInfo);
    }

    return B;
}


void GetResultOfCreateDisposition(_Inout_ PFLT_CALLBACK_DATA Data)
/*
���ܣ�����CreateDisposition��ֵ�жϳ����(OPEN,CREATE,DELETEDֻ�������֣����Ǳ�����ָ���ģ����������)��
      ����������PreCreateFile��

��һ������˼·��ֻҪ�д�������ͼ�ģ���Ϊ�����������Ƿ���ڣ��Լ�Ȩ��֮������ơ�

ע�⣺�˺�����pipe�ж���Ӱ�죬���鲻ʹ�ã������Ӧ����IsFileExist������

������
Value              Meaning
FILE_SUPERSEDE     If the file already exists, replace it with the given file. If it does not, create the given file.
FILE_CREATE        If the file already exists, fail the request and do not create or open the given file. If it does not, create the given file.
FILE_OPEN          If the file already exists, open it instead of creating a new file. If it does not, fail the request and do not create a new file.
FILE_OPEN_IF       If the file already exists, open it. If it does not, create the given file.
FILE_OVERWRITE     If the file already exists, open it and overwrite it. If it does not, fail the request.
FILE_OVERWRITE_IF  If the file already exists, open it and overwrite it. If it does not, create the given file.
������Ϣժ�ԣ�
https://docs.microsoft.com/zh-cn/windows/win32/api/winternl/nf-winternl-ntcreatefile?redirectedfrom=MSDN
http://msdn.microsoft.com/en-us/library/bb432380(v=vs.85).aspx
*/
{
    UCHAR CreateDisposition = (UCHAR)(Data->Iopb->Parameters.Create.Options >> 24);

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return;//����Ŀ¼�������Ź���
    }

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
        return;
    }

    //�����ļ������ڵģ�������ֻ�����ļ��Ѿ����ڵġ�
    if (IsFileExist(Data)) {
        switch (CreateDisposition) {
        case FILE_SUPERSEDE:
            //ret = CREATE;// FILE_CREATED;
            break;
        case FILE_CREATE:
            //ret = CREATE;// FILE_EXISTS;
            break;
        case FILE_OPEN:
            //ret = OPEN;
            break;
        case FILE_OPEN_IF:
            //ret = OPEN;
            break;
        case FILE_OVERWRITE:
            //ret = CREATE;
            break;
        case FILE_OVERWRITE_IF:
            //ret = CREATE;
            break;
        default:
            ASSERT(FALSE);
            break;
        }
    } else {
        switch (CreateDisposition) {
        case FILE_SUPERSEDE:
            //ret = CREATE;
            break;
        case FILE_CREATE:
            //ret = CREATE;
            break;
        case FILE_OPEN:
            //ret = OPEN;
            break;
        case FILE_OPEN_IF:
            ///ret = CREATE;
            break;
        case FILE_OVERWRITE:
            //ret = CREATE;
            break;
        case FILE_OVERWRITE_IF:
            //ret = CREATE;
            break;
        default:
            ASSERT(FALSE);
            break;
        }
    }

    //��������ȫ��顣

    return;//ret
}


//////////////////////////////////////////////////////////////////////////////////////////////////
