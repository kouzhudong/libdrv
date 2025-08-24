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
    OBJECT_ATTRIBUTES ob{};
    HANDLE FileHandle{};
    IO_STATUS_BLOCK  IoStatusBlock{};
    PVOID FileInformation{};
    ULONG Length = sizeof(FILE_DIRECTORY_INFORMATION);//这个数设置的太小会导致ZwQueryDirectoryFile蓝屏。
    FILE_DIRECTORY_INFORMATION * fibdi{};

    InitializeObjectAttributes(&ob, directory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    Status = ZwOpenFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ob, &IoStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
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
            FileInformation = nullptr;
        }

        FileInformation = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
        if (FileInformation == nullptr) {
            Status = STATUS_UNSUCCESSFUL;
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
            ZwClose(FileHandle);
            return Status;
        }
        RtlZeroMemory(FileInformation, Length);

        Status = ZwQueryDirectoryFile(FileHandle, nullptr, nullptr, nullptr, &IoStatusBlock, FileInformation, Length, FileDirectoryInformation, FALSE, nullptr, TRUE);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);//STATUS_BUFFER_TOO_SMALL == C0000023
            //return Status;
        }

        Length *= 2;
    } while (!NT_SUCCESS(Status));

    for (fibdi = (FILE_DIRECTORY_INFORMATION *)FileInformation;
         ;
         fibdi = (FILE_DIRECTORY_INFORMATION *)((char *)fibdi + fibdi->NextEntryOffset)) {
        UNICODE_STRING FileName{};

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
        FileInformation = nullptr;
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
    OBJECT_ATTRIBUTES ob{};
    HANDLE FileHandle{};
    IO_STATUS_BLOCK  IoStatusBlock{};
    PVOID FileInformation{};
    ULONG Length = sizeof(FILE_DIRECTORY_INFORMATION);//这个数设置的太小会导致ZwQueryDirectoryFile蓝屏。

    InitializeObjectAttributes(&ob, directory, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    Status = ZwOpenFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ob, &IoStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND || IoStatusBlock.Information == FILE_DOES_NOT_EXIST) {
            KdPrint(("file does not exist\n"));
        }
        return Status;
    }

    Length = Length + 520;//为何加这个数字，请看ZwEnumerateFile1的说明。
    FileInformation = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
    if (FileInformation == nullptr) {
        Status = STATUS_UNSUCCESSFUL;
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
        ZwClose(FileHandle);
        return Status;
    }
    RtlZeroMemory(FileInformation, Length);

    Status = ZwQueryDirectoryFile(FileHandle, nullptr, nullptr, nullptr, &IoStatusBlock, FileInformation, Length, FileDirectoryInformation, TRUE, nullptr, TRUE);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);//STATUS_BUFFER_TOO_SMALL == C0000023
        ExFreePoolWithTag(FileInformation, TAG);
        ZwClose(FileHandle);
        return Status;
    }

    do {
        UNICODE_STRING FileName{};
        FILE_DIRECTORY_INFORMATION * fibdi{};

        Status = ZwQueryDirectoryFile(FileHandle, nullptr, nullptr, nullptr, &IoStatusBlock, FileInformation, Length, FileDirectoryInformation, TRUE, nullptr, FALSE);
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
        FileInformation = nullptr;
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
    LARGE_INTEGER partitionTableOffset{};
    KEVENT event{};
    IO_STATUS_BLOCK ioStatus{};
    PIRP irp{};
    NTSTATUS Status = STATUS_SUCCESS;
    wchar_t deviceNameBuffer[128]{};
    UNICODE_STRING ObjectName{};
    PDEVICE_OBJECT DeviceObject{};//设备L"\\Device\\Harddisk%d\\DR%d" 或者 符号连接L"\\Device\\Harddisk%d\\Partition0" 所代表的对象。
    PFILE_OBJECT FileObject{};

    _swprintf(deviceNameBuffer, L"\\Device\\Harddisk%d\\Partition0", DiskIndex);
    //_swprintf(deviceNameBuffer, L"\\Device\\Harddisk%d\\DR%d", index, index);
    RtlInitUnicodeString(&ObjectName, deviceNameBuffer);
    Status = IoGetDeviceObjectPointer(&ObjectName, FILE_ALL_ACCESS, &FileObject, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        return;
    }

    partitionTableOffset.QuadPart = StartingOffset;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE, DeviceObject, Buffer, Length, &partitionTableOffset, &event, &ioStatus);
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
        (VOID)KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER)nullptr);
        Status = ioStatus.Status;
    }

    if (!NT_SUCCESS(Status)) {

    }

    ObDereferenceObject(FileObject);
}


VOID NTAPI ReadMBR(IN PDEVICE_OBJECT DeviceObject, IN ULONG SectorSize, OUT PVOID * Buffer)
{
    LARGE_INTEGER partitionTableOffset{};
    PUCHAR readBuffer = (PUCHAR)nullptr;
    KEVENT event{};
    IO_STATUS_BLOCK ioStatus{};
    PIRP irp{};
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG readSize{};

    *Buffer = nullptr;

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
    if (readBuffer == nullptr) {
        return;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, DeviceObject, readBuffer, readSize, &partitionTableOffset, &event, &ioStatus);
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
        (VOID)KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, (PLARGE_INTEGER)nullptr);
        Status = ioStatus.Status;
    }

    if (!NT_SUCCESS(Status)) {
        ExFreePool(readBuffer);
        return;
    }

    *Buffer = readBuffer;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#if (NTDDI_VERSION < NTDDI_WIN7)
//NTKERNELAPI
NTSTATUS IoReplaceFileObjectName(_In_ PFILE_OBJECT FileObject, _In_reads_bytes_(FileNameLength) PWSTR NewFileName, _In_ USHORT FileNameLength)
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

    if (fileName->Buffer != nullptr) {
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


NTSTATUS ZwGetDosFileName(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, OUT PUNICODE_STRING DosFileName)
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
    PFLT_FILE_NAME_INFORMATION nameInfo{};
    PDEVICE_OBJECT DiskDeviceObject = nullptr;
    UNICODE_STRING VolumeName{};

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
            ASSERT(nullptr != DosFileName->Buffer);
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
            PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_WARNING_LEVEL, "Status:%#X, FileName:%wZ", Status, &FltObjects->FileObject->FileName);
        }
    } else {//走这里的不少。
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_WARNING_LEVEL, "Status:%#X, FileName:%wZ", Status, &FltObjects->FileObject->FileName);//STATUS_FLT_NO_DEVICE_OBJECT
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
    OBJECT_ATTRIBUTES ob{};
    IO_STATUS_BLOCK  IoStatusBlock{};
    HANDLE FileHandle{};
    PFILE_LINK_INFORMATION FILELINKINFORMATION = nullptr;
    ULONG  Length = 0;

    /*
    一些参数的检查。
    */

    InitializeObjectAttributes(&ob, ExistingFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
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
    if (FILELINKINFORMATION == nullptr) {
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
    PDRIVER_OBJECT * DriverObjectList{};//*
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
    DriverObjectList = static_cast<PDRIVER_OBJECT *>(ExAllocatePoolWithTag(NonPagedPool, DriverObjectListSize, TAG));
    if (DriverObjectList == nullptr) {
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


#define MAX_NTFS_METADATA_FILE 11


/*
这个摘自：filemon。
*/
const CHAR * NtfsMetadataFileNames[] = {
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
FLT_ASSERT((!(Data->Iopb->TargetFileObject->FileName.Length == 0 && Data->Iopb->TargetFileObject->RelatedFileObject == nullptr)) ||
            FlagOn(Data->Iopb->TargetFileObject->Flags, FO_VOLUME_OPEN));

made by correy
made at 2016/4/11
http://correy.webs.com
*/
{
    FILE_INTERNAL_INFORMATION fileInternalInfo{};
    ULONG LengthReturned = 0;
    NTSTATUS Status = FltQueryInformationFile(Instance, FileObject, &fileInternalInfo, sizeof(fileInternalInfo), FileInternalInformation, &LengthReturned);
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
    HANDLE FileHandle = nullptr;
    OBJECT_ATTRIBUTES objAttributes{};
    IO_STATUS_BLOCK ioStatusBlock{};
    BOOL B = FALSE;
    PFLT_FILE_NAME_INFORMATION NameInfo = nullptr;

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

        InitializeObjectAttributes(&objAttributes, &NameInfo->Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
        Status = FltCreateFile(nullptr,
                               Data->Iopb->TargetInstance,//FltObjects->Instance,
                               &FileHandle,
                               FILE_GENERIC_READ | SYNCHRONIZE,
                               &objAttributes,
                               &ioStatusBlock,
                               nullptr,
                               FILE_ATTRIBUTE_NORMAL,
                               FILE_SHARE_VALID_FLAGS,
                               FILE_OPEN,
                               FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                               nullptr,
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
    UCHAR CreateDisposition = static_cast<UCHAR>(Data->Iopb->Parameters.Create.Options >> 24);

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
