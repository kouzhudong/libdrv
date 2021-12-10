#include "log.h"


#pragma warning(disable:4244) //�ӡ�unsigned __int64��ת������UCHAR�������ܶ�ʧ����
#pragma warning(disable:4267) //�ӡ�size_t��ת������UCHAR�������ܶ�ʧ����

#pragma warning(disable:28719) //Banned API Usage:  wcscpy
#pragma warning(disable:28719) //Banned API Usage:  wcsncpy

#pragma warning(disable:4996)
#pragma warning(disable:6387)


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS EventLog(__in struct _DRIVER_OBJECT * DriverObject)
/*
�ı�������Ϊ��IoAllocateErrorLogEntry.C�ɣ�
made by correy
made at 2013.05.07

�տ�ʼ������Ϊ������mc�ļ���������ʱ����־�أ�
��ʵ����Ҫmc�ļ�Ҳ����������־��
������Ҫmc�ļ�����ʱ����־Ҳ���ѣ��ܼ򵥣�source�������һ�д���Ϳ��Ա����ˡ�
���������ñ�дmc�ļ���
������дmc�ļ�Ҳ���ѡ�
��������鷳�������ҾͲ���mc�ļ��ˡ�


����Լ������������Լ��Ĵ����룺�����޸ģ�
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\System\DriverName�����ֵ
EventMessageFile (REG_EXPAND_SZ) �� TypesSupported (REG_DWORD)
�տ�ʼ�һ���Ϊ�����ɼ�¼��Ҫ������أ�


�ο����ϣ�
http://msdn.microsoft.com/en-us/library/windows/hardware/ff560866(v=vs.85).aspx
http://blog.csdn.net/peterwtu/article/details/8179674
http://driverentry.com.br/en/blog/?p=324
http://driverentry.com.br/en/blog/?p=348
http://www.osronline.com/showThread.cfm?link=28746
http://hi.baidu.com/wesley0312/item/a35737511c3e13dbd58bac51
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PVOID p = 0;
    PIO_ERROR_LOG_PACKET pioelp;

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //����һ��

    p = IoAllocateErrorLogEntry(
        DriverObject, //Ҳ���ԣ�Pointer to a device object representing the device on which an I/O error occurred,
        sizeof(IO_ERROR_LOG_PACKET) //sizeof(IO_ERROR_LOG_PACKET) + size of the DumpData member + combined size of any driver-supplied insertion strings.
    );

    //Drivers must not treat IoAllocateErrorLogEntry returning NULL as a fatal error. 
    //The driver must continue to function normally, whether or not it can log errors. 
    if (p == NULL) {
        return status;
    }

    pioelp = (PIO_ERROR_LOG_PACKET)p;
    RtlZeroMemory(p, sizeof(IO_ERROR_LOG_PACKET));
    pioelp->ErrorCode = 9;//�鿴��־��ʱ����ʾ���ǵ�:ʱ��id == 9

    //IoWriteErrorLogEntry frees the error log entry. 
    //Drivers must not call IoFreeErrorLogEntry on a log entry that they have already passed to IoWriteErrorLogEntry.
    IoWriteErrorLogEntry(p);

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //������������һ�㡣

    p = IoAllocateErrorLogEntry(DriverObject, sizeof(IO_ERROR_LOG_PACKET) + sizeof(ULONG));
    if (p == NULL) {
        return status;
    }

    pioelp = (PIO_ERROR_LOG_PACKET)p;
    RtlZeroMemory(p, sizeof(IO_ERROR_LOG_PACKET));
    pioelp->ErrorCode = 9;//�鿴��־��ʱ����ʾ���ǵ�:ʱ��id == 9
    pioelp->DumpData[0] = 0x12345678;//�������Ҳ����ʾ��Ҫ������������ҡ�
    pioelp->DumpDataSize = sizeof(ULONG);

    IoWriteErrorLogEntry(p);

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //���������ٸ���һ�㣬��������ϢҲ��һ�㡣

    {
        UNICODE_STRING          usNtStatus = {0};
        ANSI_STRING             asNtStatus;
        UCHAR                   ucFinalSize;
        PWSTR                   pwzTarget;
        PIO_ERROR_LOG_PACKET    pLogPacket;
        wchar_t ErroeMessage[] = L"made by correy"; //�����Ϣ��ʾ��ǰ�档

        RtlInitAnsiString(&asNtStatus, "QQ��112426112"); //�����Ϣ��ʾ�ں��档
        RtlAnsiStringToUnicodeString(&usNtStatus, &asNtStatus, TRUE);
        ASSERT(usNtStatus.Buffer);

        ucFinalSize = sizeof(IO_ERROR_LOG_PACKET) +
            sizeof(ULONG) +
            usNtStatus.Length +
            sizeof(WCHAR) +
            (wcslen(ErroeMessage) + 1) * sizeof(WCHAR);
        pLogPacket = (PIO_ERROR_LOG_PACKET)IoAllocateErrorLogEntry(DriverObject, ucFinalSize);

        RtlZeroMemory(pLogPacket, sizeof(IO_ERROR_LOG_PACKET));

        //A variable-size array that can be used to store driver-specific binary data, 
        //Drivers must specify the size, in bytes, of the array in the DumpDataSize member of this structure. 
        pLogPacket->DumpData[0] = 0x12345678;//�о������ʾ��ûɶ�á�

        //Indicates the size, in bytes, of the variable-length DumpData member of this structure. 
        //The specified value must be a multiple of sizeof(ULONG). 
        pLogPacket->DumpDataSize = sizeof(ULONG);//������DumpData�ĸ��� * sizeof(ULONG)

        //Indicates the offset, in bytes, from the beginning of the structure, at which any driver-supplied insertion string data begins.
        //Normally this will be sizeof(IO_ERROR_LOG_PACKET) plus the value of the DumpDataSize member. 
        //If there are no driver-supplied insertion strings, StringOffset can be zero. 
        pLogPacket->StringOffset = sizeof(IO_ERROR_LOG_PACKET) + pLogPacket->DumpDataSize;

        //Indicates the number of insertion strings the driver will supply with this error log entry. 
        //Drivers set this value to zero for errors that need no insertion strings. 
        //The Event Viewer uses these strings to fill in the "%2" through "%n" entries in the string template for this error code.
        //The null-terminated Unicode strings themselves follow the IO_ERROR_LOG_PACKET structure in memory.
        pLogPacket->NumberOfStrings = 2;//�������ַ�����

        //����ErroeMessage��Ϣ
        pwzTarget = (PWSTR)((PCHAR)pLogPacket + pLogPacket->StringOffset);
        wcscpy(pwzTarget, ErroeMessage);//׷�����ݡ�׷������õ��ôʡ� The strcpy function copies strSource, including the terminating null character

        //����usNtStatus��Ϣ
        pwzTarget += wcslen(ErroeMessage) + 1;//�����һ��0.��������һ��0.
        wcsncpy(pwzTarget, usNtStatus.Buffer, usNtStatus.Length / sizeof(WCHAR));//׷�����ݡ��о�û�бȽ����ַ����ṹ��UNICODE_STRING��ANSI_STRING

        pwzTarget += usNtStatus.Length / sizeof(WCHAR);
        *pwzTarget = 0;//��β���㡣

        //Specifies the type of error. 
        //The Event Viewer uses the error code to determine which string to display as the Description value for the error. 
        //The Event Viewer takes the string template for the error supplied in the driver's message catalog, 
        //replaces "%1" in the template with the name of the driver's device object,
        //and replaces "%2" through "%n" with the insertion strings supplied with the error log entry.
        //ErrorCode is a system-defined or driver-defined constant; 
        pLogPacket->ErrorCode = 9;//�����ֵΪ0x12345678���õ��Ľ��Ϊ�� 22136 == 0x5678.ע������ṹ�������Ա�Ĵ�С��

        //���и���Ĳ���û����д��

        IoWriteErrorLogEntry(pLogPacket);

        RtlFreeUnicodeString(&usNtStatus);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////

    return status;//STATUS_SUCCESS
}


//////////////////////////////////////////////////////////////////////////////////////////////////
