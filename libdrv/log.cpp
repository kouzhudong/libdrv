#include "log.h"


#pragma warning(disable:4244) //从“unsigned __int64”转换到“UCHAR”，可能丢失数据
#pragma warning(disable:4267) //从“size_t”转换到“UCHAR”，可能丢失数据

#pragma warning(disable:28719) //Banned API Usage:  wcscpy
#pragma warning(disable:28719) //Banned API Usage:  wcsncpy

#pragma warning(disable:4996)
#pragma warning(disable:6387)


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS EventLog(__in struct _DRIVER_OBJECT * DriverObject)
/*
文本就命名为：IoAllocateErrorLogEntry.C吧！
made by correy
made at 2013.05.07

刚开始，我以为必须有mc文件才能生成时间日志呢？
其实不需要mc文件也可以生成日志。
不过需要mc文件生成时间日志也不难，很简单，source里面加入一行代码就可以编译了。
不过，还得编写mc文件。
不过编写mc文件也不难。
不过这很麻烦，所以我就不用mc文件了。


如果自己的驱动定义自己的错误码：可以修改：
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\System\DriverName下面的值
EventMessageFile (REG_EXPAND_SZ) 和 TypesSupported (REG_DWORD)
刚开始我还以为是生成记录需要添加这呢！


参考资料：
http://msdn.microsoft.com/en-us/library/windows/hardware/ff560866(v=vs.85).aspx
http://blog.csdn.net/peterwtu/article/details/8179674
http://driverentry.com.br/en/blog/?p=324
http://driverentry.com.br/en/blog/?p=348
http://www.osronline.com/showThread.cfm?link=28746
http://hi.baidu.com/wesley0312/item/a35737511c3e13dbd58bac51
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PVOID p{};
    PIO_ERROR_LOG_PACKET pioelp{};

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //方法一：

    p = IoAllocateErrorLogEntry(
        DriverObject, //也可以：Pointer to a device object representing the device on which an I/O error occurred,
        sizeof(IO_ERROR_LOG_PACKET) //sizeof(IO_ERROR_LOG_PACKET) + size of the DumpData member + combined size of any driver-supplied insertion strings.
    );

    //Drivers must not treat IoAllocateErrorLogEntry returning NULL as a fatal error. 
    //The driver must continue to function normally, whether or not it can log errors. 
    if (p == nullptr) {
        return Status;
    }

    pioelp = static_cast<PIO_ERROR_LOG_PACKET>(p);
    RtlZeroMemory(p, sizeof(IO_ERROR_LOG_PACKET));
    pioelp->ErrorCode = 9;//查看日志的时候显示的是的:时间id == 9

    //IoWriteErrorLogEntry frees the error log entry. 
    //Drivers must not call IoFreeErrorLogEntry on a log entry that they have already passed to IoWriteErrorLogEntry.
    IoWriteErrorLogEntry(p);

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //方法二：复杂一点。

    p = IoAllocateErrorLogEntry(DriverObject, sizeof(IO_ERROR_LOG_PACKET) + sizeof(ULONG));
    if (p == nullptr) {
        return Status;
    }

    pioelp = static_cast<PIO_ERROR_LOG_PACKET>(p);
    RtlZeroMemory(p, sizeof(IO_ERROR_LOG_PACKET));
    pioelp->ErrorCode = 9;//查看日志的时候显示的是的:时间id == 9
    pioelp->DumpData[0] = 0x12345678;//不过这个也能显示，要在数据里面查找。
    pioelp->DumpDataSize = sizeof(ULONG);

    IoWriteErrorLogEntry(p);

    //////////////////////////////////////////////////////////////////////////////////////////////////
    //方法三：再复杂一点，包含的信息也多一点。

    {
        UNICODE_STRING          usNtStatus{};
        ANSI_STRING             asNtStatus{};
        UCHAR                   ucFinalSize{};
        PWSTR                   pwzTarget;
        PIO_ERROR_LOG_PACKET    pLogPacket{};
        const wchar_t ErroeMessage[] = L"made by correy"; //这个信息显示在前面。

        RtlInitAnsiString(&asNtStatus, "QQ：112426112"); //这个信息显示在后面。
        RtlAnsiStringToUnicodeString(&usNtStatus, &asNtStatus, TRUE);
        ASSERT(usNtStatus.Buffer);

        ucFinalSize = sizeof(IO_ERROR_LOG_PACKET) +
            sizeof(ULONG) +
            usNtStatus.Length +
            sizeof(WCHAR) +
            (wcslen(ErroeMessage) + 1) * sizeof(WCHAR);
        pLogPacket = static_cast<PIO_ERROR_LOG_PACKET>(IoAllocateErrorLogEntry(DriverObject, ucFinalSize));

        RtlZeroMemory(pLogPacket, sizeof(IO_ERROR_LOG_PACKET));

        //A variable-size array that can be used to store driver-specific binary data, 
        //Drivers must specify the size, in bytes, of the array in the DumpDataSize member of this structure. 
        pLogPacket->DumpData[0] = 0x12345678;//感觉这个显示的没啥用。

        //Indicates the size, in bytes, of the variable-length DumpData member of this structure. 
        //The specified value must be a multiple of sizeof(ULONG). 
        pLogPacket->DumpDataSize = sizeof(ULONG);//估计是DumpData的个数 * sizeof(ULONG)

        //Indicates the offset, in bytes, from the beginning of the structure, at which any driver-supplied insertion string data begins.
        //Normally this will be sizeof(IO_ERROR_LOG_PACKET) plus the value of the DumpDataSize member. 
        //If there are no driver-supplied insertion strings, StringOffset can be zero. 
        pLogPacket->StringOffset = sizeof(IO_ERROR_LOG_PACKET) + pLogPacket->DumpDataSize;

        //Indicates the number of insertion strings the driver will supply with this error log entry. 
        //Drivers set this value to zero for errors that need no insertion strings. 
        //The Event Viewer uses these strings to fill in the "%2" through "%n" entries in the string template for this error code.
        //The null-terminated Unicode strings themselves follow the IO_ERROR_LOG_PACKET structure in memory.
        pLogPacket->NumberOfStrings = 2;//有两个字符串。

        //复制ErroeMessage信息
        pwzTarget = reinterpret_cast<PWSTR>(reinterpret_cast<PCHAR>(pLogPacket) + pLogPacket->StringOffset);
        wcscpy(pwzTarget, ErroeMessage);//追加数据。追加是最好的用词。 The strcpy function copies strSource, including the terminating null character

        //复制usNtStatus信息
        pwzTarget += wcslen(ErroeMessage) + 1;//这个空一个0.就是跳过一个0.
        wcsncpy(pwzTarget, usNtStatus.Buffer, usNtStatus.Length / sizeof(WCHAR));//追加数据。感觉没有比较用字符串结构：UNICODE_STRING和ANSI_STRING

        pwzTarget += usNtStatus.Length / sizeof(WCHAR);
        *pwzTarget = 0;//结尾置零。

        //Specifies the type of error. 
        //The Event Viewer uses the error code to determine which string to display as the Description value for the error. 
        //The Event Viewer takes the string template for the error supplied in the driver's message catalog, 
        //replaces "%1" in the template with the name of the driver's device object,
        //and replaces "%2" through "%n" with the insertion strings supplied with the error log entry.
        //ErrorCode is a system-defined or driver-defined constant; 
        pLogPacket->ErrorCode = 9;//如果赋值为0x12345678，得到的结果为： 22136 == 0x5678.注意这个结构的这个成员的大小。

        //还有更多的参数没有填写。

        IoWriteErrorLogEntry(pLogPacket);

        RtlFreeUnicodeString(&usNtStatus);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////

    return Status;//STATUS_SUCCESS
}


//////////////////////////////////////////////////////////////////////////////////////////////////
