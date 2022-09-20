#include "pch.h"
#include "FileTest.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS ReadMBRTest()
/*
目的：驱动中读取MBR。

参考资料：
1.WRK的HalExamineMBR和IopCreateArcNamesDisk函数。
2.https://technet.microsoft.com/en-us/library/cc976786.aspx
  https://technet.microsoft.com/en-us/library/ee126177(v=ws.10).aspx

made by correy
made at 2016.10.28.
homepage:http://correy.webs.com

读取MBR的测试例子。
*/
{
    NTSTATUS status = STATUS_SUCCESS;
    wchar_t deviceNameBuffer[128];
    UNICODE_STRING deviceNameUnicodeString;
    PDEVICE_OBJECT deviceObject;
    PFILE_OBJECT fileObject;
    PIRP irp;
    DISK_GEOMETRY diskGeometry;
    KEVENT event = {};
    IO_STATUS_BLOCK ioStatusBlock;
    PVOID mbr;

    _swprintf(deviceNameBuffer, L"\\Device\\Harddisk%d\\Partition0", 0);
    RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
    status = IoGetDeviceObjectPointer(&deviceNameUnicodeString,
                                      FILE_READ_ATTRIBUTES,
                                      &fileObject,
                                      &deviceObject);

    irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                        deviceObject,
                                        NULL,
                                        0,
                                        &diskGeometry,
                                        sizeof(DISK_GEOMETRY),
                                        FALSE,
                                        &event,
                                        &ioStatusBlock);
    if (!irp) {
        ObDereferenceObject(fileObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    status = IoCallDriver(deviceObject, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }
    ASSERT(NT_SUCCESS(status));

    if (diskGeometry.BytesPerSector < 512) {// Make sure sector size is at least 512 bytes.
        diskGeometry.BytesPerSector = 512;
    }

    ReadMBR(deviceObject, diskGeometry.BytesPerSector, &mbr);

    if (mbr) {
        ExFreePool(mbr);
    }

    ObDereferenceObject(fileObject);

    return status;
}


VOID TestHardLink()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING HardLinkFileName = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\HardLink.txt");
    UNICODE_STRING ExistingFileName = RTL_CONSTANT_STRING(L"\\Device\\HarddiskVolume1\\test.txt");

    status = ZwCreateHardLink(&HardLinkFileName, &ExistingFileName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("ZwCreateHardLink fail %d\n", status));
    }
}


//////////////////////////////////////////////////////////////////////////////////////////////////
