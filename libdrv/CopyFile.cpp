#include "pch.h"
#include "CopyFile.h"


//////////////////////////////////////////////////////////////////////////////////////////////////
//���´���ժ��OSR.


#define KFC_MAX_TRANSFER_SIZE (0x10000)


static NTSTATUS KfcIoCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
//  This routine is used to handle I/O (read OR write) completion
// Inputs:
//  DeviceObject - not used
//  Irp - the I/O operation being completed
//  Context - not used
// Returns:
//  STATUS_MORE_PROCESSING_REQUIRED
// Notes:
//  The purpose of this routine is to do "cleanup" on I/O operations so we don't constantly throw away perfectly good MDLs as part of completion processing.
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    *Irp->UserIosb = Irp->IoStatus;// Copy the Status information back into the "user" IOSB.   
    KeSetEvent(Irp->UserEvent, 0, FALSE);// Set the user event - wakes up the mainline code doing this.   
    IoFreeIrp(Irp);// Free the IRP now that we are done with it.

    // We return STATUS_MORE_PROCESSING_REQUIRED because this "magic" return value
    // tells the I/O Manager that additional processing will be done by this driver to the IRP - in fact, it might (as it is in this case) already BE done - and the IRP cannot be completed.   
    return STATUS_MORE_PROCESSING_REQUIRED;
}


static VOID KfcGetFileStandardInformation(PFILE_OBJECT FileObject,
                                          PFILE_STANDARD_INFORMATION StandardInformation,
                                          PIO_STATUS_BLOCK IoStatusBlock
)
//  This function retrieves the "standard" information for the underlying file system.
// Inputs:
//  FileObject - the file to retrieve information about
// Outputs:
//  StandardInformation - the buffer where the data should be stored
//  IoStatusBlock - information about what actually happened.
// Notes:
//  This is equivalent to ZwQueryInformationFile, for FILE_STANDARD_INFORMATION
{
    PIRP irp;
    PDEVICE_OBJECT fsdDevice = IoGetRelatedDeviceObject(FileObject);
    KEVENT event;
    PIO_STACK_LOCATION ioStackLocation;

    // Start off on the right foot - zero the information block.
    RtlZeroMemory(StandardInformation, sizeof(FILE_STANDARD_INFORMATION));

    // Allocate an irp for this request.  This could also come from a private pool, for instance.
    irp = IoAllocateIrp(fsdDevice->StackSize, FALSE);
    if (!irp) {

        return;// Failure!
    }

    irp->AssociatedIrp.SystemBuffer = StandardInformation;
    irp->UserEvent = &event;
    irp->UserIosb = IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irp->RequestorMode = KernelMode;

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);// Initialize the event

    // Set up the I/O stack location.
    ioStackLocation = IoGetNextIrpStackLocation(irp);
    ioStackLocation->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    ioStackLocation->DeviceObject = fsdDevice;
    ioStackLocation->FileObject = FileObject;
    ioStackLocation->Parameters.QueryFile.Length = sizeof(FILE_STANDARD_INFORMATION);
    ioStackLocation->Parameters.QueryFile.FileInformationClass = FileStandardInformation;

    IoSetCompletionRoutine(irp, KfcIoCompletion, 0, TRUE, TRUE, TRUE);// Set the completion routine.
    (void)IoCallDriver(fsdDevice, irp);// Send it to the FSD
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);// Wait for the I/O
}


static VOID KfcRead(PFILE_OBJECT FileObject,
                    PLARGE_INTEGER Offset,
                    ULONG Length,
                    PMDL Mdl,
                    PIO_STATUS_BLOCK IoStatusBlock)
{
    PIRP irp;
    KEVENT event;
    PIO_STACK_LOCATION ioStackLocation;
    PDEVICE_OBJECT fsdDevice = IoGetRelatedDeviceObject(FileObject);

    if (nullptr == Mdl) {
        return;
    }

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);// Set up the event we'll use.   
    irp = IoAllocateIrp(fsdDevice->StackSize, FALSE);// Allocate and build the IRP we'll be sending to the FSD.    
    if (!irp) {
        IoStatusBlock->Status = STATUS_INSUFFICIENT_RESOURCES;// Allocation failed, presumably due to memory allocation failure.
        IoStatusBlock->Information = 0;
        return;
    }

    irp->MdlAddress = Mdl;
    irp->UserEvent = &event;
    irp->UserIosb = IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irp->RequestorMode = KernelMode;
    irp->Flags = IRP_READ_OPERATION;// Indicate that this is a READ operation.

    // Set up the next I/O stack location.  These are the parameters that will be passed to the underlying driver.   
    ioStackLocation = IoGetNextIrpStackLocation(irp);
    ioStackLocation->MajorFunction = IRP_MJ_READ;
    ioStackLocation->MinorFunction = 0;
    ioStackLocation->DeviceObject = fsdDevice;
    ioStackLocation->FileObject = FileObject;

    // We use a completion routine to keep the I/O Manager from doing "cleanup" on our IRP - like freeing our MDL.   
    IoSetCompletionRoutine(irp, KfcIoCompletion, 0, TRUE, TRUE, TRUE);
    ioStackLocation->Parameters.Read.Length = Length;
    ioStackLocation->Parameters.Read.ByteOffset = *Offset;

    (void)IoCallDriver(fsdDevice, irp);// Send it on.  Ignore the return code.   
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);// Wait for the I/O to complete.    
    // Done.  Return results are in the io Status block.
}


static VOID KfcSetFileAllocation(PFILE_OBJECT FileObject,
                                 PLARGE_INTEGER AllocationSize,
                                 PIO_STATUS_BLOCK IoStatusBlock
)
//  This routine sets a file's ALLOCATION size to the specified value.
//  Note that this DOES NOT extend the file's EOF.
// Inputs:
//  FileObject - the file on which to set the allocation size
//  AllocationSize - the new allocation size
// Ouputs:
//  IoStatusBlock - the results of this operation
{
    PIRP irp;
    PDEVICE_OBJECT fsdDevice = IoGetRelatedDeviceObject(FileObject);
    KEVENT event;
    PIO_STACK_LOCATION ioStackLocation;

    // Allocate an irp for this request.  This could also come from a private pool, for instance.   
    irp = IoAllocateIrp(fsdDevice->StackSize, FALSE);
    if (!irp) {
        return;// Failure!
    }

    irp->AssociatedIrp.SystemBuffer = AllocationSize;
    irp->UserEvent = &event;
    irp->UserIosb = IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irp->RequestorMode = KernelMode;

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);// Initialize the event

    // Set up the I/O stack location.
    ioStackLocation = IoGetNextIrpStackLocation(irp);
    ioStackLocation->MajorFunction = IRP_MJ_SET_INFORMATION;
    ioStackLocation->DeviceObject = fsdDevice;
    ioStackLocation->FileObject = FileObject;
    ioStackLocation->Parameters.SetFile.Length = sizeof(LARGE_INTEGER);
    ioStackLocation->Parameters.SetFile.FileInformationClass = FileAllocationInformation;
    ioStackLocation->Parameters.SetFile.FileObject = 0; // not used for allocation    
    ioStackLocation->Parameters.SetFile.AdvanceOnly = FALSE;

    IoSetCompletionRoutine(irp, KfcIoCompletion, 0, TRUE, TRUE, TRUE);// Set the completion routine.
    (void)IoCallDriver(fsdDevice, irp);// Send it to the FSD
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);// Wait for the I/O
}


static VOID KfcWrite(PFILE_OBJECT FileObject,
                     PLARGE_INTEGER Offset,
                     ULONG Length,
                     PMDL Mdl,
                     PIO_STATUS_BLOCK IoStatusBlock)
{
    PIRP irp;
    KEVENT event;
    PIO_STACK_LOCATION ioStackLocation;
    PDEVICE_OBJECT fsdDevice = IoGetRelatedDeviceObject(FileObject);

    if (nullptr == Mdl) {
        return;
    }

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);// Set up the event we'll use.    
    irp = IoAllocateIrp(fsdDevice->StackSize, FALSE);// Allocate and build the IRP we'll be sending to the FSD.       
    if (!irp) {
        IoStatusBlock->Status = STATUS_INSUFFICIENT_RESOURCES;// Allocation failed, presumably due to memory allocation failure.        
        IoStatusBlock->Information = 0;
        return;
    }

    irp->MdlAddress = Mdl;
    irp->UserEvent = &event;
    irp->UserIosb = IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = FileObject;
    irp->RequestorMode = KernelMode;
    irp->Flags = IRP_WRITE_OPERATION;// Indicate that this is a WRITE operation.

    // Set up the next I/O stack location.  These are the parameters that will be passed to the underlying driver.   
    ioStackLocation = IoGetNextIrpStackLocation(irp);
    ioStackLocation->MajorFunction = IRP_MJ_WRITE;
    ioStackLocation->MinorFunction = 0;
    ioStackLocation->DeviceObject = fsdDevice;
    ioStackLocation->FileObject = FileObject;

    // We use a completion routine to keep the I/O Manager from doing "cleanup" on our IRP - like freeing our MDL.   
    IoSetCompletionRoutine(irp, KfcIoCompletion, 0, TRUE, TRUE, TRUE);
    ioStackLocation->Parameters.Write.Length = Length;
    ioStackLocation->Parameters.Write.ByteOffset = *Offset;

    (void)IoCallDriver(fsdDevice, irp);// Send it on.  Ignore the return code.   
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);// Wait for the I/O to complete.    
    // Done.  Return results are in the io Status block.
}


NTSTATUS KfcCopyFile(PFILE_OBJECT TargetFileObject, PFILE_OBJECT SourceFileObject)
//  This routine implements the fast file copy code.
// Inputs:
//  TargetFileObject - copying TO
//  SourceFileObject - copying FROM
// Returns:
//  SUCCESS when it works, otherwise an appropriate error
{
    PVOID buffer;
    PMDL mdl;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION standardInformation;
    LARGE_INTEGER currentOffset;
    LONGLONG bytesToTransfer;

    // The algorithm used by this routine is straight-forward: read 64k chunks from the source file and write it to the target file, until the entire file itself has been copied.   
    buffer = ExAllocatePoolWithTag(NonPagedPool, KFC_MAX_TRANSFER_SIZE, TAG);
    if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;// Allocation must have failed.        
    }

    // Build an MDL describing the buffer.  We'll use THAT to do the I/O (rather than a direct buffer address.)   
    mdl = IoAllocateMdl(buffer, KFC_MAX_TRANSFER_SIZE, FALSE, TRUE, 0);
    MmBuildMdlForNonPagedPool(mdl);
    currentOffset.QuadPart = 0;// Set up the current offset information   

    KfcGetFileStandardInformation(SourceFileObject, &standardInformation, &iosb);// Get the size of the input file.    
    if (!NT_SUCCESS(iosb.Status)) {
        KdPrint(("KfcGetFileStandardInformation failed: 0x%0x\r\n", iosb.Status));
        ExFreePoolWithTag(buffer, TAG);
        return (iosb.Status);// This is a failure condition.        
    }

    KfcSetFileAllocation(TargetFileObject, &standardInformation.AllocationSize, &iosb); // Set the allocation size of the output file.      
    if (!NT_SUCCESS(iosb.Status)) {
        KdPrint(("SetFileAllocation failed: 0x%0x\r\n", iosb.Status));
        ExFreePoolWithTag(buffer, TAG);
        return (iosb.Status);// Failure...        
    }

    bytesToTransfer = standardInformation.EndOfFile.QuadPart;// Save away the information about the # of bytes to transfer.   

    // Now copy the source to the target until we run out...   
    while (bytesToTransfer) {
        ULONG nextTransferSize;

        // The # of bytes to copy in the next operation is based upon the maximum of the balance IN the file, or KFC_MAX_TRANSFER_SIZE       
        nextTransferSize = (bytesToTransfer < KFC_MAX_TRANSFER_SIZE) ? (ULONG)bytesToTransfer : KFC_MAX_TRANSFER_SIZE;
        KfcRead(SourceFileObject, &currentOffset, nextTransferSize, mdl, &iosb);
        if (!NT_SUCCESS(iosb.Status)) {

            if (iosb.Status != STATUS_END_OF_FILE) {
                ExFreePoolWithTag(buffer, TAG);
                return (iosb.Status);// An error condition occurred.  
            }
        }

        KfcWrite(TargetFileObject, &currentOffset, nextTransferSize, mdl, &iosb);
        if (!NT_SUCCESS(iosb.Status)) {
            ExFreePoolWithTag(buffer, TAG);
            return (iosb.Status);// An error condition occurred.            
        }

        // Now, update the offset/bytes to transfer information       
        currentOffset.QuadPart += nextTransferSize;
        bytesToTransfer -= nextTransferSize;
    }

    ExFreePoolWithTag(buffer, TAG);
    return (STATUS_SUCCESS);// At this point, we're done with the copy operation.  Return success
}


NTSTATUS IrpCopyFile(UNICODE_STRING * name, UNICODE_STRING * newFileName)
/*
ͨ��IRP��ʽ�����ļ���

ע�⣺
    1.��CREATE��Ϣ����ò�Ҫʹ�ô˺�����
    2.���Դ�ļ����������������Ҳ��ʧ�ܵġ����˼·�ǣ�FsRtlCreateSectionForDataScan��
    3.˽�е���Ҫ��Ҫ���ơ�
*/
{
    OBJECT_ATTRIBUTES ob;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    HANDLE source_fileHandle, target_fileHandle;
    PFILE_OBJECT source, target;
    NTSTATUS Status;
    LARGE_INTEGER AllocationSize = {0};

    InitializeObjectAttributes(&ob, name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenFile(&source_fileHandle,
                        FILE_GENERIC_READ | SYNCHRONIZE,
                        &ob,
                        &IoStatusBlock,
                        FILE_SHARE_VALID_FLAGS, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status)) {

        return Status;
    }

    InitializeObjectAttributes(&ob, newFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    //Status = ZwOpenFile(&target_fileHandle, FILE_GENERIC_READ | SYNCHRONIZE, &ob, &IoStatusBlock, FILE_SHARE_VALID_FLAGS, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    Status = ZwCreateFile(&target_fileHandle,
                          FILE_ALL_ACCESS | SYNCHRONIZE,
                          &ob,
                          &IoStatusBlock,
                          &AllocationSize,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_VALID_FLAGS,
                          FILE_OPEN_IF,
                          FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    if (!NT_SUCCESS(Status)) {

        ZwClose(source_fileHandle);
        return Status;
    }

    Status = ObReferenceObjectByHandle(source_fileHandle,
                                       FILE_READ_ACCESS,
                                       *IoFileObjectType,
                                       KernelMode,
                                       (PVOID *)&source,
                                       0);
    if (!NT_SUCCESS(Status)) {

        ZwClose(source_fileHandle);
        ZwClose(target_fileHandle);
        return Status;
    }

    Status = ObReferenceObjectByHandle(target_fileHandle,
                                       FILE_WRITE_ACCESS,
                                       *IoFileObjectType,
                                       KernelMode,
                                       (PVOID *)&target,
                                       0);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ObDereferenceObject(source);// Failure to dereference the object will cause file object leakage in the system. 
        ZwClose(source_fileHandle);
        ZwClose(target_fileHandle);
        return Status;
    }

    // If we get to this point, we perform the copy.       
    Status = KfcCopyFile(target, source);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
    }

    // Now release the file object references   
    ZwClose(source_fileHandle);
    ZwClose(target_fileHandle);
    ObDereferenceObject(source);
    ObDereferenceObject(target);

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
����:���������ļ�.

�ļ������ܼ�.
NT*ϵ�к����Ĳ������û���Ҳ����.

Ϊ���н��������?
�ļ�������ļ���?���걾ƪ��֪����.
Ϊ��Ҫ��ZW*ϵ�к���?���ں���û��Ȩ�޵�����,��֪���ı�������Ǹ��ط�����˵��.
�������ں˾Ϳ�����һЩӦ�ò�����������,����Ҫ��������Ȩ�޵�.

����û�п�����ص�ʾ������.
ֻ��WDK�ϵ�һЩ�򵥵Ľ���:Using Files In A Driver
http://msdn.microsoft.com/en-us/library/windows/hardware/ff565384(v=vs.85).aspx

ǰ��������������������ʧ��:
��:windows\\system32\\config\\sam
�ᵼ��:C0000043 == -1073741757,������:��һ����������ʹ�ô��ļ��������޷����ʡ�
�����Ƕ�ռ��ʽ�򿪵�.

made by correy
made at 2013.11.23
����֮��,����ָ��.
*/


BOOLEAN CopyFile(IN PWCH DestinationFile, IN PWCH SourceFile, IN BOOLEAN bFailIfExists)
/*
��������ʽΪ:C:\WINDOWS\example.txt

bFailIfExists == TRUEʱ,���DestinationFile���ھͷ���ʧ��;
bFailIfExists == FALSEʱ,���DestinationFile���ھ��½����߸���;

���ڵ�ȱ����:
1.û�и����ļ�������,��:�ļ��������ߵ���Ϣ.
*/
{
    BOOLEAN b = FALSE;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING df = {0};
    UNICODE_STRING f = RTL_CONSTANT_STRING(L"\\??\\");//On Microsoft Windows 2000 and later versions of the operating system, \?? is equivalent to \DosDevices.
    OBJECT_ATTRIBUTES ob;
    HANDLE FileHandle = 0;
    HANDLE DestinationFileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    PVOID Buffer = 0;
    ULONG Length = 0;
    LARGE_INTEGER file_size = {0};
    LARGE_INTEGER ByteOffset = {0};
    LARGE_INTEGER i = {0};
    FILE_STANDARD_INFORMATION fsi = {0};
    LARGE_INTEGER AllocationSize = {0};
    ULONG CreateDisposition = 0;

    //���SourceFile���ļ���,������򿪵�ʱ�򷵻�ʧ��.

    __try {
        df.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH, TAG);
        if (df.Buffer == NULL) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
            __leave;
        }
        RtlZeroMemory(df.Buffer, MAX_PATH);
        RtlInitEmptyUnicodeString(&df, df.Buffer, MAX_PATH);
        RtlCopyUnicodeString(&df, &f);
        Status = RtlAppendUnicodeToString(&df, SourceFile);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }
        InitializeObjectAttributes(&ob, &df, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
        Status = ZwOpenFile(&FileHandle,
                            GENERIC_READ | SYNCHRONIZE,
                            &ob,
                            &IoStatusBlock,
                            FILE_SHARE_READ,
                            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
                KdPrint(("file does not exist\n"));
            }
            if (IoStatusBlock.Information == FILE_DOES_NOT_EXIST) {
                KdPrint(("file does not exist\n"));
            }
            __leave;
        }

        RtlZeroMemory(df.Buffer, MAX_PATH);
        RtlInitEmptyUnicodeString(&df, df.Buffer, MAX_PATH);
        RtlCopyUnicodeString(&df, &f);
        Status = RtlAppendUnicodeToString(&df, DestinationFile);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }
        InitializeObjectAttributes(&ob, &df, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
        if (bFailIfExists) {
            CreateDisposition = FILE_CREATE;//�½��ļ�.
        } else {
            CreateDisposition = FILE_SUPERSEDE;//FILE_OVERWRITE_IF
        }
        Status = ZwCreateFile(&DestinationFileHandle,
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
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        //���Կ�����������ļ�����,����,���ñ�Ĳ�����д��.ZwLockFile,�����ʵ���ʱ�����:ZwUnlockFile.

        Status = ZwQueryInformationFile(FileHandle,
                                        &IoStatusBlock,
                                        &fsi,
                                        sizeof(FILE_STANDARD_INFORMATION),
                                        FileStandardInformation);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            __leave;
        }

        if (fsi.EndOfFile.QuadPart == 0) {
            __leave;
        }

        file_size = fsi.EndOfFile;
        Length = 9;//����ZwQuerySystemInformation SystemBasicInformationȡҳ�Ĵ�С��
        Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);
        if (Buffer == NULL) {
            Status = STATUS_UNSUCCESSFUL;
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
            __leave;
        }

        for (; i.QuadPart < file_size.QuadPart; ) {
            RtlZeroMemory(Buffer, Length);

            Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, Length, &i, NULL);
            if (!NT_SUCCESS(Status)) {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
                __leave;
            }

            Status = ZwWriteFile(DestinationFileHandle,
                                 NULL,
                                 NULL,
                                 NULL,
                                 &IoStatusBlock,
                                 Buffer,
                                 (ULONG)IoStatusBlock.Information,
                                 &i,
                                 NULL);
            if (!NT_SUCCESS(Status)) //���Լ��д�����������д���������
            {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
                __leave;
            }

            i.QuadPart += IoStatusBlock.Information;//�����������ZwWriteFile��ǰ��ͻ���ִ�С�����⡣
        }
    } __finally {
        if (NT_SUCCESS(Status)) //���������������.
        {
            b = TRUE;//��ʱд�ļ��᷵��0x103,���ص� I/O �����ڽ�����,Ҳ���ߵ�����.
        }

        //�رվ��.        
        if (FileHandle) {
            Status = ZwClose(FileHandle);
            if (!NT_SUCCESS(Status)) {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            }
        }
        if (DestinationFileHandle) {
            Status = ZwClose(DestinationFileHandle);
            if (!NT_SUCCESS(Status)) {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            }
        }

        //�ͷ��ڴ�.
        if (df.Buffer) {
            ExFreePoolWithTag(df.Buffer, TAG);
        }
        if (Buffer) {
            ExFreePoolWithTag(Buffer, TAG);
        }
    }

    return b;//����ͬ����Ҫ������.
}


BOOLEAN CopyFileEx(IN UNICODE_STRING * FileName, IN UNICODE_STRING * newFileName) //CONST
    /*
    ��������ʽ�ǣ�"\Device\HarddiskVolume1\XXX�ȡ�

    ���ڵ�ȱ����:
    1.û�и����ļ�������,��:�ļ��������ߵ���Ϣ.
    */
{
    BOOLEAN b = FALSE;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob;
    HANDLE FileHandle = 0;
    HANDLE DestinationFileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    PVOID Buffer = 0;
    ULONG Length = 0;
    ULONG CreateDisposition = 0;
    FILE_STANDARD_INFORMATION fsi = {0};
    LARGE_INTEGER ByteOffset = {0};
    LARGE_INTEGER AllocationSize = {0};
    LARGE_INTEGER file_size = {0};

    InitializeObjectAttributes(&ob, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwOpenFile(&FileHandle,
                        GENERIC_READ | SYNCHRONIZE,
                        &ob,
                        &IoStatusBlock,
                        FILE_SHARE_READ,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status)) {
        //KdPrint(("ZwOpenFile fail with 0x%x.\n", Status));
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
            KdPrint(("file does not exist\n"));
        }
        if (IoStatusBlock.Information == FILE_DOES_NOT_EXIST) {
            KdPrint(("file does not exist\n"));
        }
        return b;
    }

    //���Կ�����������ļ�����,����,���ñ�Ĳ�����д��.ZwLockFile,�����ʵ���ʱ�����:ZwUnlockFile.

    Status = ZwQueryInformationFile(FileHandle,
                                    &IoStatusBlock,
                                    &fsi,
                                    sizeof(FILE_STANDARD_INFORMATION),
                                    FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ZwClose(FileHandle);
        return b;;
    }

    //�½��ļ�.
    CreateDisposition = FILE_CREATE;
    InitializeObjectAttributes(&ob, newFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwCreateFile(&DestinationFileHandle,
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
    if (!NT_SUCCESS(Status)) {
        //KdPrint(("ZwCreateFile fail with 0x%x.\n", Status));
        ZwClose(FileHandle);
        if (Status == STATUS_OBJECT_NAME_COLLISION) {//-1073741771 ((NTSTATUS)0xC0000035L) Object Name already exists.
            b = TRUE;
        }
        return b;
    }

    if (fsi.EndOfFile.QuadPart == 0) {
        ZwClose(FileHandle);
        ZwClose(DestinationFileHandle);
        return TRUE;
    }

    file_size = fsi.EndOfFile;
    Length = 9;//����ר�á�
    Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);//Length == 0ʱ��������֤���������������
    if (Buffer == NULL) {
        Status = STATUS_UNSUCCESSFUL;
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
        ZwClose(FileHandle);
        ZwClose(DestinationFileHandle);
        return b;
    }

    for (; ByteOffset.QuadPart < file_size.QuadPart; ) {
        RtlZeroMemory(Buffer, Length);

        Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, Length, &ByteOffset, NULL);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            ExFreePoolWithTag(Buffer, TAG);
            ZwClose(FileHandle);
            ZwClose(DestinationFileHandle);
            return b;
        }

        Status = ZwWriteFile(DestinationFileHandle,
                             NULL,
                             NULL,
                             NULL,
                             &IoStatusBlock,
                             Buffer,
                             (ULONG)IoStatusBlock.Information,
                             &ByteOffset,
                             NULL);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            ExFreePoolWithTag(Buffer, TAG);
            ZwClose(FileHandle);
            ZwClose(DestinationFileHandle);
            return b;
        }

        ByteOffset.QuadPart += IoStatusBlock.Information;
    }

    ExFreePoolWithTag(Buffer, TAG);
    ZwClose(FileHandle);
    ZwClose(DestinationFileHandle);

    return TRUE;
}


BOOLEAN ZwCopyFile(IN UNICODE_STRING * FileName, IN UNICODE_STRING * newFileName) //CONST
    /*
    ��������ʽ�ǣ�"\Device\HarddiskVolume1\XXX����\\??\\c:\\WINDOWS\\system32\\config\\SAM��

    ���ܣ�����ר�Ÿ��Ʊ���ռʽʹ�õ��ļ������ҳ�ļ�������ʹ�õ�pagefile.sys���͸��ֱ�����ʹ��HIVE�ļ�.
    ��չ���ܣ���ɾ���ļ����򿪵�ʱ�����ɾ�������ԣ�FILE_DELETE_ON_CLOSE ������Ҳ���Եģ�������÷���IRP����������ʽ�ϡ�

    ˵����IoCreateFileEx������IO_IGNORE_SHARE_ACCESS_CHECK���ܣ�����This routine is available starting with Windows Vista.

    ���ڵ�ȱ����:
    1.û�и����ļ�������,��:�ļ��������ߵ���Ϣ.

    made by correy
    made at 2014.07.28
    */
{
    BOOLEAN b = FALSE;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob;
    HANDLE FileHandle = 0;
    HANDLE DestinationFileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    PVOID Buffer = 0;
    ULONG Length = 0;
    ULONG CreateDisposition = 0;
    FILE_STANDARD_INFORMATION fsi = {0};
    LARGE_INTEGER ByteOffset = {0};
    LARGE_INTEGER AllocationSize = {0};
    LARGE_INTEGER file_size = {0};
    FILE_FULL_EA_INFORMATION ffai = {0};

    InitializeObjectAttributes(&ob, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    //Status = ZwOpenFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ob, &IoStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    //if (!NT_SUCCESS (Status)) 
    //{
    //    //KdPrint(("ZwOpenFile fail with 0x%x.\n", Status));
    //    if ( Status == STATUS_OBJECT_NAME_NOT_FOUND)  {
    //        KdPrint(("file does not exist\n"));
    //    }
    //    if (IoStatusBlock.Information == FILE_DOES_NOT_EXIST ) {
    //        KdPrint(("file does not exist\n"));
    //    }
    //    return b;
    //}
    Status = IoCreateFileSpecifyDeviceObjectHint(
        &FileHandle,
        GENERIC_READ | SYNCHRONIZE,
        &ob,
        &IoStatusBlock,
        &AllocationSize,
        FILE_ATTRIBUTE_NORMAL,
        /*
        Specifies the type of share access to the file that the caller would like, as zero, or one, or a combination of the following flags.
        To request exclusive access, set this parameter to zero.
        If the IO_IGNORE_SHARE_ACCESS_CHECK flag is specified in the Options parameter, the I/O manager ignores this parameter.
        However, the file system might still perform access checks.
        Thus, it is important to specify the sharing mode you would like for this parameter, even when using the IO_IGNORE_SHARE_ACCESS_CHECK flag.
        For the greatest chance of avoiding sharing violation errors, specify all of the following share access flags.
        */
        FILE_SHARE_VALID_FLAGS,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        &ffai,
        sizeof(FILE_FULL_EA_INFORMATION),
        CreateFileTypeNone,//��ʵ�����ܵ����ʼ���Ҳ�����ˡ�
        NULL,
        /*
        Indicates that the I/O manager should not perform share-access checks on the file object after it is created.
        However, the file system might still perform these checks.
        */
        IO_IGNORE_SHARE_ACCESS_CHECK,
        /*
        A pointer to the device object to which the create request is to be sent.
        The device object must be a filter or file system device object in the file system driver stack for the volume on which the file or directory resides.
        This parameter is optional and can be NULL. If this parameter is NULL, the request will be sent to the device object at the top of the driver stack.
        */
        NULL);
    if (!NT_SUCCESS(Status)) {
        //KdPrint(("ZwOpenFile fail with 0x%x.\n", Status));
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
            KdPrint(("file does not exist\n"));
        }
        if (IoStatusBlock.Information == FILE_DOES_NOT_EXIST) {
            KdPrint(("file does not exist\n"));
        }
        return b;
    }

    //���Կ�����������ļ�����,����,���ñ�Ĳ�����д��.ZwLockFile,�����ʵ���ʱ�����:ZwUnlockFile.
    //����This routine is available in Windows 7 and later versions of the Windows operating system.

    Status = ZwQueryInformationFile(FileHandle,
                                    &IoStatusBlock,
                                    &fsi,
                                    sizeof(FILE_STANDARD_INFORMATION),
                                    FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ZwClose(FileHandle);
        return b;;
    }

    //�½��ļ�.
    CreateDisposition = FILE_CREATE;
    InitializeObjectAttributes(&ob, newFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwCreateFile(&DestinationFileHandle,
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
    if (!NT_SUCCESS(Status)) {
        //KdPrint(("ZwCreateFile fail with 0x%x.\n", Status));
        ZwClose(FileHandle);
        if (Status == STATUS_OBJECT_NAME_COLLISION) {//-1073741771 ((NTSTATUS)0xC0000035L) Object Name already exists.
            b = TRUE;
        }
        return b;
    }

    if (fsi.EndOfFile.QuadPart == 0) {
        ZwClose(FileHandle);
        ZwClose(DestinationFileHandle);
        return TRUE;
    }

    file_size = fsi.EndOfFile;
    Length = 9;//����ר�á�
    Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);//Length == 0ʱ��������֤���������������
    if (Buffer == NULL) {
        Status = STATUS_UNSUCCESSFUL;
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
        ZwClose(FileHandle);
        ZwClose(DestinationFileHandle);
        return b;
    }

    for (; ByteOffset.QuadPart < file_size.QuadPart; ) {
        RtlZeroMemory(Buffer, Length);

        Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, Length, &ByteOffset, NULL);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            ExFreePoolWithTag(Buffer, TAG);
            ZwClose(FileHandle);
            ZwClose(DestinationFileHandle);
            return b;
        }

        Status = ZwWriteFile(DestinationFileHandle,
                             NULL,
                             NULL,
                             NULL,
                             &IoStatusBlock,
                             Buffer,
                             (ULONG)IoStatusBlock.Information,
                             &ByteOffset,
                             NULL);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            ExFreePoolWithTag(Buffer, TAG);
            ZwClose(FileHandle);
            ZwClose(DestinationFileHandle);
            return b;
        }

        ByteOffset.QuadPart += IoStatusBlock.Information;
    }

    ExFreePoolWithTag(Buffer, TAG);
    ZwClose(FileHandle);
    ZwClose(DestinationFileHandle);

    return TRUE;
}


/*
* ��������ʾ����
*
    UNICODE_STRING FileName  = RTL_CONSTANT_STRING(L"\\??\\c:\\1.exe");
    UNICODE_STRING newFileName  = RTL_CONSTANT_STRING(L"\\??\\c:\\3.exe");
    UNICODE_STRING FileName2  = RTL_CONSTANT_STRING(L"\\??\\c:\\WINDOWS\\system32\\config\\SAM");
    UNICODE_STRING newFileName2  = RTL_CONSTANT_STRING(L"\\??\\c:\\WINDOWS\\system32\\config\\SAM2");
    UNICODE_STRING FileName3  = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\WINDOWS\\system32\\config\\SAM");//
    UNICODE_STRING newFileName3  = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\WINDOWS\\system32\\config\\SAM3");

    if (!CopyFile(L"c:\\1.exe", L"c:\\2.exe", FALSE))
    {
        KdPrint(("copy_file fail!\n"));
    }

    if (!CopyFileEx(&FileName, &newFileName))
    {
        KdPrint(("copy_file_ex fail!\n"));
    }

    if (!ZwCopyFile(&FileName2, &newFileName2))
    {
        KdPrint(("copy_file_ex2 fail!\n"));
    }

    if (!ZwCopyFile(&FileName3, &newFileName3))
    {
        KdPrint(("copy_file_ex2 fail!\n"));
    }
*/


BOOLEAN IoCopyFile(IN UNICODE_STRING * FileName, IN UNICODE_STRING * newFileName) //CONST
    /*
    ��������ʽ�ǣ�"\Device\HarddiskVolume1\XXX����\\??\\c:\\WINDOWS\\system32\\config\\SAM��

    ���ܣ����ƶ�ռʽ�ĺͱ�������ZwLockFile�����ļ���

    ˵����
    1.IoCreateFileEx������IO_IGNORE_SHARE_ACCESS_CHECK���ܣ�����This routine is available starting with Windows Vista.
    2.����ר�Ÿ��Ʊ���ռʽʹ�õ��ļ������ҳ�ļ�������ʹ�õ�pagefile.sys���͸��ֱ�����ʹ��HIVE�ļ�.
    3.��չ���ܣ���ɾ���ļ����򿪵�ʱ�����ɾ�������ԣ�FILE_DELETE_ON_CLOSE ������Ҳ���Եģ�������÷���IRP����������ʽ�ϡ�

    ���ڵ�ȱ����:
    1.û�и����ļ�������,��:�ļ��������ߵ���Ϣ.

    made by correy
    made at 2015.01.04
    */

    /*
    //���������ļ�һ��
    //UNICODE_STRING FileName2  = RTL_CONSTANT_STRING(L"\\??\\c:\\test1.txt");
    //UNICODE_STRING newFileName2  = RTL_CONSTANT_STRING(L"\\??\\c:\\test2.txt");
    //UNICODE_STRING FileName3  = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\test1.txt");//
    //UNICODE_STRING newFileName3  = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\test3.txt");

    //���������ļ�����
    UNICODE_STRING FileName2  = RTL_CONSTANT_STRING(L"\\??\\c:\\WINDOWS\\system32\\config\\SAM");
    UNICODE_STRING newFileName2  = RTL_CONSTANT_STRING(L"\\??\\c:\\WINDOWS\\system32\\config\\SAM2");
    UNICODE_STRING FileName3  = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\WINDOWS\\system32\\config\\SAM");//
    UNICODE_STRING newFileName3  = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\WINDOWS\\system32\\config\\SAM3");

    KdBreakPoint();

    DriverObject->DriverUnload = DriverUnload;

    if (!copy_file_ex3(&FileName2, &newFileName2))
    {
        KdPrint(("copy_file_ex3 fail!\n"));
    }

    if (!copy_file_ex3(&FileName3, &newFileName3))
    {
        KdPrint(("copy_file_ex3 fail!\n"));
    }
    */
{
    BOOLEAN b = FALSE;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob;
    HANDLE FileHandle = 0;
    HANDLE DestinationFileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    SIZE_T Length = 0;
    ULONG CreateDisposition = 0;
    FILE_STANDARD_INFORMATION fsi = {0};
    LARGE_INTEGER ByteOffset = {0};
    LARGE_INTEGER AllocationSize = {0};
    LARGE_INTEGER file_size = {0};
    FILE_FULL_EA_INFORMATION ffai = {0};
    HANDLE SectionHandle = 0;
    PVOID BaseAddress = 0;
    SIZE_T ViewSize = 0;

    InitializeObjectAttributes(&ob, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    //Status = ZwOpenFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ob, &IoStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    //if (!NT_SUCCESS (Status)) 
    //{
    //    //KdPrint(("ZwOpenFile fail with 0x%x.\n", Status));
    //    if ( Status == STATUS_OBJECT_NAME_NOT_FOUND)  {
    //        KdPrint(("file does not exist\n"));
    //    }
    //    if (IoStatusBlock.Information == FILE_DOES_NOT_EXIST ) {
    //        KdPrint(("file does not exist\n"));
    //    }
    //    return b;
    //}
    Status = IoCreateFileSpecifyDeviceObjectHint(
        &FileHandle,
        GENERIC_READ | SYNCHRONIZE,
        &ob,
        &IoStatusBlock,
        &AllocationSize,
        FILE_ATTRIBUTE_NORMAL,
        /*
        Specifies the type of share access to the file that the caller would like, as zero, or one, or a combination of the following flags.
        To request exclusive access, set this parameter to zero.
        If the IO_IGNORE_SHARE_ACCESS_CHECK flag is specified in the Options parameter, the I/O manager ignores this parameter.
        However, the file system might still perform access checks.
        Thus, it is important to specify the sharing mode you would like for this parameter, even when using the IO_IGNORE_SHARE_ACCESS_CHECK flag.
        For the greatest chance of avoiding sharing violation errors, specify all of the following share access flags.
        */
        FILE_SHARE_VALID_FLAGS,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        &ffai,
        sizeof(FILE_FULL_EA_INFORMATION),
        CreateFileTypeNone,//��ʵ�����ܵ����ʼ���Ҳ�����ˡ�
        NULL,
        /*
        Indicates that the I/O manager should not perform share-access checks on the file object after it is created.
        However, the file system might still perform these checks.
        */
        IO_IGNORE_SHARE_ACCESS_CHECK,
        /*
        A pointer to the device object to which the create request is to be sent.
        The device object must be a filter or file system device object in the file system driver stack for the volume on which the file or directory resides.
        This parameter is optional and can be NULL. If this parameter is NULL, the request will be sent to the device object at the top of the driver stack.
        */
        NULL);
    if (!NT_SUCCESS(Status)) {
        //KdPrint(("ZwOpenFile fail with 0x%x.\n", Status));
        if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
            KdPrint(("file does not exist\n"));
        }
        if (IoStatusBlock.Information == FILE_DOES_NOT_EXIST) {
            KdPrint(("file does not exist\n"));
        }
        return b;
    }

    //���Կ�����������ļ�����,����,���ñ�Ĳ�����д��.ZwLockFile,�����ʵ���ʱ�����:ZwUnlockFile.
    //����This routine is available in Windows 7 and later versions of the Windows operating system.
    //����NtLockFile��NtUnlockFile��XP�µ���������ʹ�á�

    Status = ZwQueryInformationFile(FileHandle,
                                    &IoStatusBlock,
                                    &fsi,
                                    sizeof(FILE_STANDARD_INFORMATION),
                                    FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ZwClose(FileHandle);
        return b;;
    }

    //�½��ļ�.
    CreateDisposition = FILE_OVERWRITE_IF;
    InitializeObjectAttributes(&ob, newFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = ZwCreateFile(&DestinationFileHandle,
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
    if (!NT_SUCCESS(Status)) {
        //KdPrint(("ZwCreateFile fail with 0x%x.\n", Status));
        ZwClose(FileHandle);
        if (Status == STATUS_OBJECT_NAME_COLLISION) {//-1073741771 ((NTSTATUS)0xC0000035L) Object Name already exists.
            b = TRUE;
        }
        return b;
    }

    //�ļ���СΪ�㣬�ͽ����ˡ�
    if (fsi.EndOfFile.QuadPart == 0) {
        ZwClose(FileHandle);
        ZwClose(DestinationFileHandle);
        return TRUE;
    }

    //���������4G���ļ���
    if (fsi.EndOfFile.HighPart != 0) {
        ZwClose(FileHandle);
        ZwClose(DestinationFileHandle);
        return TRUE;
    }

    file_size = fsi.EndOfFile;
    Length = PAGE_SIZE;//����ר�á�
    //Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);//Length == 0ʱ��������֤���������������
    //if (Buffer == NULL) { 
    //    Status = STATUS_UNSUCCESSFUL;
    //    Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
    //    ZwClose(FileHandle);
    //    ZwClose(DestinationFileHandle);
    //    return b;
    //}

    InitializeObjectAttributes(&ob, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);//���Բ���������������·����
    Status = ZwCreateSection(&SectionHandle,
                             SECTION_MAP_READ | SECTION_QUERY,
                             &ob,
                             &fsi.EndOfFile,
                             PAGE_READONLY,
                             SEC_COMMIT,
                             FileHandle);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        //ExFreePoolWithTag(Buffer, TAG);
        ZwClose(FileHandle);
        ZwClose(DestinationFileHandle);
        return b;
    }

    /*
    ����һҳ����һҳ���ݵĶ�ȡ�ġ�
    ����������ȫ����ȡ�ˡ�
    */
    //for ( ;ByteOffset.QuadPart < file_size.QuadPart ; ) 
    {
        //RtlZeroMemory(Buffer, Length);

        //Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Buffer, Length, &ByteOffset, NULL);
        //if (!NT_SUCCESS (Status)) //���ڴ������ļ��Ĵ򿪻�ʧ�ܡ�
        //{
        //    KdPrint(("ZwReadFile fail with 0x%x.\n", Status));
        //    ExFreePoolWithTag(Buffer, TAG);
        //    ZwClose(FileHandle);
        //    ZwClose(DestinationFileHandle);
        //    return b;
        //}

        //ע�⣺�����Ȩ�޺������Ȩ��Ҫ��Ӧ��
        Status = ZwMapViewOfSection(SectionHandle,
                                    ZwCurrentProcess(),
                                    &BaseAddress,
                                    0,
                                    0,
                                    NULL,
                                    &ViewSize/* &Length*/,
                                    ViewShare,
                                    0 /*MEM_COMMIT*/,
                                    PAGE_READONLY);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            //ExFreePoolWithTag(Buffer, TAG);
            ZwClose(SectionHandle);
            ZwClose(FileHandle);
            ZwClose(DestinationFileHandle);
            return b;
        }

        //���Ҫ�������4G��������Ӹ�ѭ������������4G������Ҳ����ӳ��ɹ���
        Status = ZwWriteFile(DestinationFileHandle,
                             NULL,
                             NULL,
                             NULL,
                             &IoStatusBlock,
                             /*Buffer*/ BaseAddress,
                             fsi.EndOfFile.LowPart /*ViewSize  Length  IoStatusBlock.Information*/,//��ʱû�д������4G���ļ���
                             &ByteOffset,
                             NULL);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            //ExFreePoolWithTag(Buffer, TAG);
            ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
            ZwClose(SectionHandle);
            ZwClose(FileHandle);
            ZwClose(DestinationFileHandle);
            return b;
        }

        //ByteOffset.QuadPart += IoStatusBlock.Information;

        ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
    }

    //ExFreePoolWithTag(Buffer, TAG);
    ZwClose(SectionHandle);
    ZwClose(FileHandle);
    ZwClose(DestinationFileHandle);

    return TRUE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOLEAN FltCopyFile(_In_ PFLT_FILTER Filter,
                    __inout PFLT_CALLBACK_DATA Data,
                    IN UNICODE_STRING * FileName,
                    IN UNICODE_STRING * newFileName
)
/*
��������ʽ�ǣ�"\Device\HarddiskVolume1\XXX�ȡ�

���ڵ�ȱ����:
1.û�и����ļ�������,��:�ļ��������ߵ���Ϣ.
*/
{
    BOOLEAN b = FALSE;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES ob = {0};
    HANDLE FileHandle = 0;
    HANDLE DestinationFileHandle = 0;
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    PVOID Buffer = 0;
    ULONG Length = 0;
    ULONG CreateDisposition = 0;
    FILE_STANDARD_INFORMATION fsi = {0};
    LARGE_INTEGER ByteOffset = {0};
    LARGE_INTEGER AllocationSize = {0};
    LARGE_INTEGER file_size = {0};
    BOOL IS_HAVE_slash = FALSE;
    LARGE_INTEGER LIboffs = {0};
    FILE_FULL_EA_INFORMATION ffai = {0};
    PFILE_OBJECT  source_FileObject = 0;

    if (NULL == FileName || NULL == newFileName) {
        return b;
    }

    InitializeObjectAttributes(&ob, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = FltCreateFile(//FltCreateFileEx��XP SP2��û�е�����
                           Filter,
                           Data->Iopb->TargetInstance,//FltObjects->Instance,
                           &FileHandle,
                           //&source_FileObject,
                           FILE_GENERIC_READ | SYNCHRONIZE,
                           &ob,
                           &IoStatusBlock,
                           0,
                           FILE_ATTRIBUTE_NORMAL,
                           FILE_SHARE_VALID_FLAGS, //������ԣ����������ǶԵġ�
                           FILE_OPEN,
                           FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                           NULL,
                           0,
                           IO_IGNORE_SHARE_ACCESS_CHECK);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x, file:%wZ", Status, FileName);
        return b;
    }

    Status = ObReferenceObjectByHandle(FileHandle,
                                       FILE_LIST_DIRECTORY | SYNCHRONIZE,
                                       *IoFileObjectType,
                                       KernelMode,
                                       (PVOID *)&source_FileObject,
                                       NULL);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x, file:%wZ", Status, FileName);
        ZwClose(FileHandle);
        return b;
    }

    Status = FsRtlGetFileSize(source_FileObject, &file_size);
    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
        ObDereferenceObject(source_FileObject);
        ZwClose(FileHandle);
        return b;;
    }

    ////���Կ�����������ļ�����,����,���ñ�Ĳ�����д��.ZwLockFile,�����ʵ���ʱ�����:ZwUnlockFile.
    //Status = NtLockFile(FileHandle, 0, 0, 0, &IoStatusBlock, &LIboffs, &fsi.EndOfFile, 0, TRUE, FALSE);
    //if (!NT_SUCCESS (Status)) 
    //{
    //    KdPrint(("NtLockFile fail with 0x%x.\r\n", Status));
    //    ZwClose(FileHandle);
    //    return b;;
    //}

    //ȥ����׺��б�ܡ�
    if (newFileName->Buffer[newFileName->Length / 2 - 1] == L'\\') {
        newFileName->Length -= 2;
        IS_HAVE_slash = TRUE;
    }

    //�½��ļ�.
    AllocationSize.QuadPart = 0;
    CreateDisposition = FILE_CREATE;
    InitializeObjectAttributes(&ob, newFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
    Status = FltCreateFile(Filter,
                           Data->Iopb->TargetInstance,
                           &DestinationFileHandle,
                           FILE_ALL_ACCESS | SYNCHRONIZE,
                           &ob,
                           &IoStatusBlock,
                           0,
                           FILE_ATTRIBUTE_NORMAL,
                           FILE_SHARE_VALID_FLAGS, //������ԣ����������ǶԵġ�
                           FILE_OPEN_IF,
                           FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                           NULL,
                           0,
                           IO_IGNORE_SHARE_ACCESS_CHECK);
    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_OBJECT_NAME_COLLISION) {//-1073741771 ((NTSTATUS)0xC0000035L) Object Name already exists.
            b = TRUE;//Ŀ���ļ��Ѿ������ˣ����Է�����ȷ��
        } else { //����NTFS��Ԫ�ļ�/���ļ�����ռʽ���ʵ��ļ��������Ӧ����ǰ��Ź�NTFS��Ԫ�ļ���
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x, file:%wZ", Status, newFileName);
            b = FALSE;//�ٴ�����ʧ�ܣ�Ҳ����Ϊ�ϵ�ʹ�á�
        }

        //�ָ���׺��б�ܡ�
        if (IS_HAVE_slash) {
            newFileName->Length += 2;
            IS_HAVE_slash = FALSE;
        }

        //Status =  NtUnlockFile(FileHandle, &IoStatusBlock, &LIboffs, &fsi.EndOfFile, 0);
        return b;
    }

    if (file_size.QuadPart == 0) {
        //Status =  NtUnlockFile(FileHandle, &IoStatusBlock, &LIboffs, &fsi.EndOfFile, 0);
        ObDereferenceObject(source_FileObject);
        ZwClose(FileHandle);
        ZwClose(DestinationFileHandle);
        return TRUE;
    }

    Length = 0x1000;//����ר�á�
    Buffer = ExAllocatePoolWithTag(NonPagedPool, Length, TAG);//Length == 0ʱ��������֤���������������
    if (Buffer == NULL) {
        Status = STATUS_UNSUCCESSFUL;
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
        //Status =  NtUnlockFile(FileHandle, &IoStatusBlock, &LIboffs, &fsi.EndOfFile, 0);
        ObDereferenceObject(source_FileObject);
        ZwClose(DestinationFileHandle);
        ZwClose(FileHandle);
        return b;
    }

    for (; ByteOffset.QuadPart < file_size.QuadPart; ) {
        ULONG  BytesRead = 0;
        RtlZeroMemory(Buffer, Length);

        Status = FltReadFile(Data->Iopb->TargetInstance,
                             source_FileObject,
                             &ByteOffset,
                             Length,
                             Buffer,
                             //FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, // | FLTFL_IO_OPERATION_PAGING | FLTFL_IO_OPERATION_NON_CACHED
                             FLTFL_IO_OPERATION_PAGING, //
                             &BytesRead,
                             NULL,
                             NULL);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            ExFreePoolWithTag(Buffer, TAG);
            ObDereferenceObject(source_FileObject);
            ZwClose(DestinationFileHandle);
            ZwClose(FileHandle);
            return b;
        }

        Status = ZwWriteFile(DestinationFileHandle,
                             NULL,
                             NULL,
                             NULL,
                             &IoStatusBlock,
                             Buffer,
                             BytesRead,
                             NULL /*&ByteOffset*/,
                             NULL);
        //Status = FltWriteFile(
        //    Data->Iopb->TargetInstance, 
        //    source_FileObject, 
        //    &ByteOffset,
        //    Length, 
        //    Buffer, 
        //    FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_PAGING, 
        //    &BytesRead,
        //    NULL, 
        //    NULL);
        if (!NT_SUCCESS(Status)) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
            ExFreePoolWithTag(Buffer, TAG);
            ObDereferenceObject(source_FileObject);
            ZwClose(DestinationFileHandle);
            ZwClose(FileHandle);
            return b;
        }

        ByteOffset.QuadPart += BytesRead;//IoStatusBlock.Information;
    }

    ExFreePoolWithTag(Buffer, TAG);
    ObDereferenceObject(source_FileObject);
    ZwClose(DestinationFileHandle);
    ZwClose(FileHandle);

    return TRUE;
}
