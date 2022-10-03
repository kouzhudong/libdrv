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
功能：在驱动中遍历/枚举文件。

看似一个简单不值一看的功能，花费了我一天的时间，也许我太笨，所以有此记录。

made by correy
made at 2014.06.04
*/


NTSTATUS ZwEnumerateFile(IN UNICODE_STRING * directory)
/*
功能：枚举目录下的文件。没有递归。

输入参数：可以是路径，句柄，文件对象，这个可以修改,但不能是文件路径。

路径的格式最好是：L"\\??\\C:\\Windows");
或者"\Device\HarddiskVolume1\XXX  \\DosDevices\\C:\\，不然还得转换，结构最好用的UNICODE_STRING，这样安全。

这个方法的思路是一下读取了一个目录下的所有信息。优缺点是不言而喻的，就是所需的内存的大小，你知道吗？

其实，ZwEnumerateFile这个函数没有获取所需的内存的大小的功能，一个思路是结构的大小加路径的大小。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob;
    HANDLE FileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    PVOID FileInformation = 0;
    ULONG Length = sizeof(FILE_DIRECTORY_INFORMATION);//这个数设置的太小会导致ZwQueryDirectoryFile蓝屏。
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
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
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
            //这里可以考虑递归。这里放弃了文件夹的显示。
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
功能：枚举目录下的文件。没有递归。

输入参数：可以是路径，句柄，文件对象，这个可以修改,但不能是文件路径。

路径的格式最好是：L"\\??\\C:\\Windows");
或者"\Device\HarddiskVolume1\XXX  \\DosDevices\\C:\\，不然还得转换，结构最好用的UNICODE_STRING，这样安全。

这个是改进版。
因为上面的函数，不可能确定目录下有多少目录，如系统目录下有几千个文件。
这个办法是一个一个来的，参考了KMDKIT的第十一章教程。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob;
    HANDLE FileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    PVOID FileInformation = 0;
    ULONG Length = sizeof(FILE_DIRECTORY_INFORMATION);//这个数设置的太小会导致ZwQueryDirectoryFile蓝屏。

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

    Length = Length + 520;//为何加这个数字，请看ZwEnumerateFile1的说明。
    FileInformation = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
    if (FileInformation == NULL) {
        Status = STATUS_UNSUCCESSFUL;
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
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
            break;//这里好像没有走过。
        }

        fibdi = (FILE_DIRECTORY_INFORMATION *)FileInformation;

        if (FILE_ATTRIBUTE_DIRECTORY == fibdi->FileAttributes) {
            //这里可以考虑递归。这里放弃了文件夹的显示。
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
    //经测试，这三种类型的路径都是可以的。
    UNICODE_STRING directory  = RTL_CONSTANT_STRING(L"\\??\\C:\\test");
    //UNICODE_STRING directory  = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\test");
    //UNICODE_STRING directory  = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\test");

    注意：
    \\Device\\HarddiskVolume1\\是可以的；
    \\Device\\HarddiskVolume1是不可以的。

    ZwEnumerateFileEx(&directory);//, FileIdBothDirectoryInformation
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID NTAPI WriteDiskSector(INT DiskIndex, LONGLONG StartingOffset, PVOID Buffer, ULONG Length)
/*
功能：写磁盘的扇区。

参数：
DiskIndex:磁盘索引。
StartingOffset：写入位置，以字节为单位，以扇区边界对齐。
Buffer：扇区的倍数。
Length：扇区的倍数。

注意：
1.如果没有设置FileObject，在Windows 10上，会蓝屏，发生在fileinfo!FIPreReadWriteCallback在调用nt!FsRtlIsPagingFile时。
2.此函数在Windows 10上会失败。
3.写第一个扇区之外的扇区会失败。
*/
{
    LARGE_INTEGER partitionTableOffset = {0};
    KEVENT event;
    IO_STATUS_BLOCK ioStatus;
    PIRP irp;
    NTSTATUS Status = STATUS_SUCCESS;
    wchar_t deviceNameBuffer[128];
    UNICODE_STRING ObjectName;
    PDEVICE_OBJECT DeviceObject;//设备L"\\Device\\Harddisk%d\\DR%d" 或者 符号连接L"\\Device\\Harddisk%d\\Partition0" 所代表的对象。
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
#pragma warning(disable:4996)//被声明为已否决
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
写这个函数的原因是：FltGetFileNameInformation对于不存在的路径会返回失败。
也许不应该这样做，实在是找不到办法了。
这里的实现办法是：如果上面的失败，就获取文件对象的内容。
*/
{
    PFLT_FILE_NAME_INFORMATION pfni;
    NTSTATUS Status = STATUS_SUCCESS;

    //函数成功了，函数外释放。
    usFullPath->Buffer = (wchar_t *)ExAllocatePoolWithTag(NonPagedPool, MAXPATHLEN, TAG);
    if (usFullPath->Buffer == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    RtlZeroMemory(usFullPath->Buffer, MAXPATHLEN);
    RtlInitEmptyUnicodeString(usFullPath, usFullPath->Buffer, MAXPATHLEN);//效果是只是改变最大值,这个结构成员.

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
            //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "文件/目录:%wZ，status:0x%#x", &FltObjects->FileObject->FileName, Status);          
        }
        SetFlag(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY);
    } else {
        Status = FltGetFileNameInformation(Cbd, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pfni);
        if (!NT_SUCCESS(Status)) {
            //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "文件/目录:%wZ，status:0x%#x", &FltObjects->FileObject->FileName, Status);
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
    为XP量身打造的FltQueryDirectoryFile
    如果要在XP下运行，请在XP下编译，否则驱动加载失败。
    This function is like ZwQueryDirectoryFile for filters
    改名为：ZwQueryDirectoryFile_LongName啥的较好。
    注意：FltQueryDirectoryFile在Vista上有，ZwQueryDirectoryFile在Xp上有。
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
功能：打印挂载的对象的信息。

此函数一般建议用在InstanceSetup中。
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
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "%s", "申请内存失败");
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
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_INFO_LEVEL, "信息：attached device:%wZ", &Volume);
    }

    ExFreePoolWithTag(Buffer, TAG);
}


NTSTATUS ZwGetDosFileName(_Inout_ PFLT_CALLBACK_DATA Data,
                          _In_ PCFLT_RELATED_OBJECTS FltObjects,
                          OUT PUNICODE_STRING DosFileName
)
/*
功能：获取文件的DOS名。
主要用于Create的前后操作，因为后面的操作肯定是从自己保持的上下文中获取的。

这里有好多没有卷的特殊的设备的操作。

这个函数的性能和功能都不如FltGetDosFileName好。
FltGetDosFileName，这个函数是自己写的，用到了卷上下文，代码这里不公布了。

IoVolumeDeviceToDosName比IoQueryFileDosDeviceName安全，因为卷已经挂载了，但是文件却不一定被打开。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PFLT_FILE_NAME_INFORMATION nameInfo;
    PDEVICE_OBJECT DiskDeviceObject = NULL;
    UNICODE_STRING VolumeName;

    Status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(Status)) {
        //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "文件/目录:%wZ，status:0x%#x", &FltObjects->FileObject->FileName, Status);//信息太多。
        return Status;//这里有返回STATUS_OBJECT_PATH_NOT_FOUND
    }

    Status = FltParseFileNameInformation(nameInfo);
    ASSERT(NT_SUCCESS(Status));

    Status = FltGetDiskDeviceObject(FltObjects->Volume, &DiskDeviceObject);
    if (NT_SUCCESS(Status)) {
        Status = IoVolumeDeviceToDosName(DiskDeviceObject, &VolumeName);//后面有冒号。
        if (NT_SUCCESS(Status)) {
            DosFileName->MaximumLength = VolumeName.MaximumLength + nameInfo->Name.MaximumLength;
            DosFileName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, DosFileName->MaximumLength, TAG);
            ASSERT(NULL != DosFileName->Buffer);
            DosFileName->Length = 0;
            RtlZeroMemory(DosFileName->Buffer, DosFileName->MaximumLength);

            RtlCopyUnicodeString(DosFileName, &VolumeName);
            //Status = RtlAppendUnicodeToString(DosFileName, L":");
            //ASSERT(NT_SUCCESS(Status));
            Status = RtlUnicodeStringCbCatN(DosFileName, &nameInfo->ParentDir, nameInfo->ParentDir.Length); //前后都有\. 
            ASSERT(NT_SUCCESS(Status));
            Status = RtlUnicodeStringCbCatN(DosFileName, &nameInfo->FinalComponent, nameInfo->FinalComponent.Length);
            ASSERT(NT_SUCCESS(Status));
        } else {
            PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_WARNING_LEVEL, "Status:%#X, FileName:%wZ",
                    Status, &FltObjects->FileObject->FileName);
        }
    } else {//走这里的不少。
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_WARNING_LEVEL, "Status:%#X, FileName:%wZ",
                Status, &FltObjects->FileObject->FileName);//STATUS_FLT_NO_DEVICE_OBJECT
    }

    FltReleaseFileNameInformation(nameInfo);

    return Status;
}


NTSTATUS ZwCreateHardLink(__in PUNICODE_STRING HardLinkFileName, __in PUNICODE_STRING  ExistingFileName)
/*
功能：创建硬链接。
注意：1.在同一个卷，
      2.ExistingFileName要存在
      3.ExistingFileName是文件
      4.ExistingFileName的链接个数不能超过1023.
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
    一些参数的检查。
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

    //建议申请内存，因为FILELINKINFORMATION->FileName的后面是秘密的内存。
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

此代码在Windows 7上测试成功。
不当之处，请指正。

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

    //XP下调用此函数没有反应。就是各个参数及返回值依旧是原来的样子。
    Status = IoEnumerateRegisteredFiltersList(DriverObjectList, DriverObjectListSize, &ActualNumberDriverObjects);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return Status;
        }
    }

    //XP下申请大小为0的内存竟然成功，而且还可以读写。
    DriverObjectListSize = ActualNumberDriverObjects * sizeof(DRIVER_OBJECT);
    DriverObjectList = (PDRIVER_OBJECT *)ExAllocatePoolWithTag(NonPagedPool, DriverObjectListSize, TAG);
    if (DriverObjectList == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    RtlZeroMemory(DriverObjectList, DriverObjectListSize);

    //XP下调用此函数仍然没有反应。就是各个参数及返回值依旧是原来的样子。
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
文件名:EnumerateFilters.C

微软不建议使用:IoEnumerateRegisteredFiltersList.

功能:enumerates all registered minifilter drivers in the system及其一些信息的显示.
目的:示例一些minifilter的一些枚举函数的用法,理解,区别.

可能要连接fltMgr.lib.
加载的方式可用一般的驱动(nt服务).

参考资料:
http://hi.baidu.com/kernelkit/item/95dab957bf115711aaf6d743
http://www.inreverse.net/?p=1334
http://blogs.msdn.com/b/alexcarp/archive/2009/08/11/issuing-io-in-minifilters-part-1-fltcreatefile.aspx
http://blogs.msdn.com/b/alexcarp/archive/2009/09/01/issuing-io-in-minifilters-part-2-flt-vs-zw.aspx
http://blogs.msdn.com/b/alexcarp/archive/2009/06/16/filter-manager-concepts-part-3-flt-filter.aspx
http://blogs.msdn.com/b/alexcarp/archive/2009/06/24/filter-manager-concepts-part-4-flt-instance.aspx
等.

不足之处,敬请指出.
made by correy
made at 2013.10.23

个人感觉FltEnumerateInstances和FltEnumerateVolumes差不多.
区别是前者能获取所有的minifilter的所有的实例的信息,后者只获取某个minifilter的所有的卷设备的信息.
相信有转换和联系的函数.

开始以为:FltEnumerateVolumes是获取的一个PFLT_FILTER过滤的卷设备的对象,不是全部的磁盘上的卷.
经测试是:获取本地计算机上的可用的卷.一下是获取不到的:
1.光驱里面没有光盘.
2.虚拟磁盘软件虚拟出来的卷设备.
3.网络映射的盘符.
4.subst命令搞出的驱动器号.
5.软盘没有测试.
这个函数的缺点是第一个参数,而且还不能是0,个人建议是去掉这个参数.
不过在minifilter驱动里面是有这个参数的.
*/


void PrintFilterFullInformation(PFLT_FILTER pf)
{
    //另一个思路是使用:FltEnumerateFilterInformation

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

    BufferSize = sizeof(PFLT_FILTER) * BytesReturned * 2;//多申请一倍.
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
    FilterName.MaximumLength = pfi->FilterNameLength;//不再加2.

    //DbgPrint("FrameID:%d\n", pfi->FrameID);
    //DbgPrint("NumberOfInstances:%d\n", pfi->NumberOfInstances);
    DbgPrint("FilterName:%wZ\n", &FilterName);

    /*
    打印的内容如下:
    FrameID:0
    NumberOfInstances:5
    FilterName:TFsFlt
    FrameID:0
    NumberOfInstances:6
    FilterName:QQSysMonX64
    FrameID:0
    NumberOfInstances:1
    FilterName:luafv 注释:微软的LUA文件虚拟化筛选器驱动程序.
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

    BufferSize = sizeof(PFLT_FILTER) * BytesReturned * 2;//多申请一倍.
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
    VolumeName.MaximumLength = pvsi->FilterVolumeNameLength;//不再加2.

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
        DbgPrint("FileSystemType :%ls\n", L"发生错误!");
        break;
    }

    //这里也要用FltObjectDereference再释放一下?
    FltObjectDereference(pv);

    ExFreePoolWithTag(Buffer, TAG);
}


void EnumerateInstances(PFLT_FILTER pf)
{
    //FltEnumerateInstances
    //FltGetInstanceInformation 这个获取的全是数字,所以放弃使用.
    //FltEnumerateInstanceInformationByFilter 这个获取的全是数字,所以放弃使用.
    //FltEnumerateInstanceInformationByVolume 这个获取的全是数字,所以放弃使用.

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

    InstanceListSize = sizeof(PFLT_INSTANCE) * NumberInstancesReturned * 2;//多申请一倍.
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
        //打印每个实例的信息.
        //相信和卷设备是一样的,转换为卷设备再打印,这里就不打印详细信息的,只打印实例的地址.
        DbgPrint("PFLT_FILTER:%p\tInstances:%p\n", pf, InstanceList[i]);

        FltObjectDereference(InstanceList[i]);
    }

    //这里也要用FltObjectDereference再释放一下?
    FltObjectDereference(pf);

    ExFreePoolWithTag(InstanceList, TAG);
}


void EnumerateVolumes(PFLT_FILTER pf)
{
    //FltEnumerateVolumes这个获取全了,要枚举.
    //FltGetVolumeInformation
    //FltEnumerateVolumeInformation这个不用,是获取单个的,要循环.

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

    VolumeListSize = sizeof(PFLT_VOLUME) * NumberVolumesReturned * 2;//多申请一倍.

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
        //打印每个卷设备的信息.
        PrintVolumeStandardInformation(VolumeList[i]);

        FltObjectDereference(VolumeList[i]);
    }

    //这里也要用FltObjectDereference再释放一下?
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
    //确保两次调用FltEnumerateFilters期间不要加载或者卸载minifilter.建议使用rundown机制.
    Status = FltEnumerateFilters(0, FilterListSize, &NumberFiltersReturned);
    if (!NT_SUCCESS(Status)) //#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
    {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return Status;
        }
    }

    //建议每次成功的调用之后都调用:VOID FltObjectDereference(_Inout_  PVOID FltObject);

    FilterListSize = sizeof(PFLT_FILTER) * NumberFiltersReturned * 2;//多申请一倍.
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

    //卸载所有已经注册的minifilter.理论上比抹去未公开的结构好.这里暂时注释掉.
    //for (i = 0;i < NumberFiltersReturned;i++)
    //{
    //    FltUnregisterFilter(FilterList[i]);//有的驱动会永远停止在这里.
    //}

    /*
    在这里可以列举一些minifilter的信息
    甚至每个minifilter过滤的每个卷设备的信息.

    PFLT_FILTER是个为公开的数据结构,各个版本的结构不一.

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

    再附加两个结构:
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

    不过建议使用:FltEnumerateFilterInformation或者FltGetFilterInformation获取各种信息.
    */

    //打印每个驱动的信息,这里选择FilterFullInformation类型.
    for (i = 0; i < NumberFiltersReturned; i++) {
        PrintFilterFullInformation(FilterList[i]);//打印系统的所有的minifilter 驱动.
        EnumerateInstances(FilterList[i]);//枚举每个minifilter驱动的每个过滤设备的实例,里面可以获取更多的信息.
        EnumerateVolumes(FilterList[i]);//枚举每个minifilter驱动的每个卷设备的信息,里面可以获取更多的信息,其实和上面的差不多.

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
效果如下:
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

验证一下:
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
这个摘自：filemon。
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
功能：识别NTFS/REFS等文件系统的元数据。

这里是：ftl的实现，还有zw的实现。

参考：
1.filemon.c
2.Windows 8 Driver Samples\Metadata Manager File System Minifilter Driver
3.passThrough

注意在卷的实例化/挂载的时候可以选择：
if (VolumeFilesystemType != FLT_FSTYPE_NTFS && VolumeFilesystemType != FLT_FSTYPE_FAT && VolumeFilesystemType != FLT_FSTYPE_REFS)
{
    Status = STATUS_NOT_SUPPORTED;
    ......
}

其实:
1.filemon很久，但是很有参考的价值。
2.Windows 8 Driver Samples\Metadata Manager File System Minifilter Driver很累赘，在win 10上好多消息都没有拦截到，可以用Procmon.exe过滤":\$"做比较.
3.所以正确的和满足自己需求的还是自己来。

//其实这个可以为过滤的条件。摘自：\Windows 8 Driver Samples\Metadata Manager File System Minifilter Driver
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
功能:判断文件存在不？
注意：这里没有考虑别的打开失败的情况。
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE FileHandle = NULL;
    OBJECT_ATTRIBUTES objAttributes = {0};
    IO_STATUS_BLOCK ioStatusBlock = {0};
    BOOL B = FALSE;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;

    if (IRP_MJ_CREATE != Data->Iopb->MajorFunction) {
        return B;//只支持这个操作。
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
        Status = FltClose(FileHandle);//严禁使用ZwClose，否者资源泄露，驱动程序验证器下会检测到。
    }

    if (NameInfo) {
        FltReleaseFileNameInformation(NameInfo);
    }

    return B;
}


void GetResultOfCreateDisposition(_Inout_ PFLT_CALLBACK_DATA Data)
/*
功能：根据CreateDisposition的值判断出结果(OPEN,CREATE,DELETED只有这三种，这是本函数指定的，规则可商讨)。
      仅仅适用于PreCreateFile。

另一做法和思路：只要有创建的意图的，都为创建，无论是否存在，以及权限之类的限制。

注意：此函数对pipe有恶劣影响，建议不使用，其核心应该是IsFileExist函数。

检查规则：
Value              Meaning
FILE_SUPERSEDE     If the file already exists, replace it with the given file. If it does not, create the given file.
FILE_CREATE        If the file already exists, fail the request and do not create or open the given file. If it does not, create the given file.
FILE_OPEN          If the file already exists, open it instead of creating a new file. If it does not, fail the request and do not create a new file.
FILE_OPEN_IF       If the file already exists, open it. If it does not, create the given file.
FILE_OVERWRITE     If the file already exists, open it and overwrite it. If it does not, fail the request.
FILE_OVERWRITE_IF  If the file already exists, open it and overwrite it. If it does not, create the given file.
以上信息摘自：
https://docs.microsoft.com/zh-cn/windows/win32/api/winternl/nf-winternl-ntcreatefile?redirectedfrom=MSDN
http://msdn.microsoft.com/en-us/library/bb432380(v=vs.85).aspx
*/
{
    UCHAR CreateDisposition = (UCHAR)(Data->Iopb->Parameters.Create.Options >> 24);

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return;//对于目录不处理，放过。
    }

    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
        return;
    }

    //对于文件不存在的，不处理，只处理文件已经存在的。
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

    //再来个安全检查。

    return;//ret
}


//////////////////////////////////////////////////////////////////////////////////////////////////
