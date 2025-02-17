#include "pch.h"
#include "misc.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_same_
_Success_(return == STATUS_SUCCESS)
NTSTATUS Sleep(_In_ UINT32 numMS)
/**
Purpose:  Delay the thread for the specified time.
MSDN_Ref: HTTP://MSDN.Microsoft.com/En-US/Library/FF551986.aspx
*/
{
    ASSERT(numMS);

    // (numMS[milli] * (-1[relative] * 1000[milli to micro] * 1000[micro to nano]) / 100[ns]
    INT64 interval = numMS * -10000i64;

    return KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)&interval);
}


#pragma alloc_text(PAGE, RtlIsNameInExpression)
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN RtlIsNameInExpression(_In_ PUNICODE_STRING Expression, _In_ PUNICODE_STRING Name)
/*
参数：
Expression是带有匹配符的字符。
Name是被搜索的字符串。

注意：不用再把Name转换成大写，因为FsRtlIsNameInExpression支持不区分大小写。

在资源不足的情况下， FsRtlIsNameInExpression 可能会引发具有STATUS_NO_MEMORY代码的结构化异常，调用方应准备好处理该异常。 
有关详细信息，请参阅 结构化异常处理。

 备注
如果只有一个字符串参数的长度为零， 则 FsRtlIsNameInExpression 返回 FALSE。 这意味着“*”与空字符串不匹配。
如果两个参数都是空字符串， 则 FsRtlIsNameInExpression 返回 TRUE。

https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtlisnameinexpression
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING  DestinationString{};
    BOOLEAN B{};

    PAGED_CODE();

    if (Expression == nullptr || Name == nullptr) {
        return FALSE;
    }

    Status = RtlUpcaseUnicodeString(&DestinationString, Expression, TRUE);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "Status:%#x", Status);
        return FALSE;
    }

    __try {
        B = FsRtlIsNameInExpression(&DestinationString, Name, TRUE, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        B = FALSE;
    }

    RtlFreeUnicodeString(&DestinationString);

    return B;
}


NTSTATUS AllocateUnicodeString(_In_ PUNICODE_STRING String)
/*++
Routine Description:
    This routine allocates a unicode string
Arguments:
    String - supplies the size of the string to be allocated in the MaximumLength field return the unicode string
Return Value:
    STATUS_SUCCESS                  - success
    STATUS_INSUFFICIENT_RESOURCES   - failure
--*/
{
    PAGED_CODE();

    String->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, String->MaximumLength, TAG);
    if (String->Buffer == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    String->Length = 0;
    return STATUS_SUCCESS;
}


VOID FreeUnicodeString(_In_ PUNICODE_STRING String)
/*++
Routine Description:
    This routine frees a unicode string
Arguments:
    String - supplies the string to be freed
--*/
{
    PAGED_CODE();

    if (String->Buffer) {
        ExFreePoolWithTag(String->Buffer, TAG);
        String->Buffer = nullptr;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = nullptr;
}


LONG ExceptionFilter(_In_ PEXCEPTION_POINTERS ExceptionPointer)
/*++
Routine Description:
Exception filter to catch errors touching user buffers.

Arguments:
ExceptionPointer - The exception record.
AccessingUserBuffer - If TRUE, overrides FsRtlIsNtStatusExpected to allow the caller to munge the error to a desired Status.

Return Value:
EXCEPTION_EXECUTE_HANDLER - If the exception handler should be run.
EXCEPTION_CONTINUE_SEARCH - If a higher exception handler should take care of this exception.

用法示例：__except (ExceptionFilter(GetExceptionInformation()))
--*/
{
#pragma warning(push)
#pragma warning(disable:4065) //switch 语句包含“default”但是未包含“case”标签
#pragma warning(disable:4189) //局部变量已初始化但不引用

    NTSTATUS Status = ExceptionPointer->ExceptionRecord->ExceptionCode;
    BOOLEAN IsNtstatusExpected = FsRtlIsNtstatusExpected(Status);

    switch (Status) {
    default:
        break;
    }

    return EXCEPTION_EXECUTE_HANDLER;

#pragma warning(pop)
}


void ConvertFormatTimeToSystemTime(IN wchar_t * rule_text, OUT PLARGE_INTEGER st)
/*
参数rule_text是本地时间的字符串。
*/
{
    PSYSTEMTIME pst = (PSYSTEMTIME)rule_text;
    TIME_FIELDS tf{};
    LARGE_INTEGER temp{};
    BOOLEAN B = FALSE;

    tf.Year = pst->wYear;
    tf.Month = pst->wMonth;
    tf.Day = pst->wDay;
    tf.Hour = pst->wHour;
    tf.Minute = pst->wMinute;
    tf.Second = pst->wSecond;
    tf.Milliseconds = pst->wMilliseconds;
    tf.Weekday = pst->wDayOfWeek;

    B = RtlTimeFieldsToTime(&tf, &temp);
    ASSERT(B);

    ExLocalTimeToSystemTime(&temp, st);
}


void ConvertSystemTimeToFormatTime(IN PLARGE_INTEGER st, OUT PUNICODE_STRING TimeString)
/*
参数rule_text是本地时间的字符串。
*/
{
    TIME_FIELDS tf{};
    NTSTATUS Status;

    RtlTimeToTimeFields(st, &tf);

    Status = RtlStringCbPrintfW(TimeString->Buffer, 
                                TimeString->MaximumLength,
                                L"%04d-%02d-%02d %02d:%02d:%02d",
                                tf.Year,
                                tf.Month,
                                tf.Day,
                                tf.Hour,
                                tf.Minute,
                                tf.Second);
    ASSERT(NT_SUCCESS(Status));

    TimeString->Length = (USHORT)wcsnlen(TimeString->Buffer, TimeString->MaximumLength);
}


void StringToInteger(wchar_t * rule_text, PULONG y)
{
    NTSTATUS Status{};
    UNICODE_STRING rule{};

    RtlInitUnicodeString(&rule, rule_text);

    Status = RtlUnicodeStringToInteger(&rule, 0, y);
    ASSERT(NT_SUCCESS(Status));
}


ULONG GetCurrnetTime()
{
    ULONG ulRet = 0;
    LARGE_INTEGER CurrentTime{};

    KeQuerySystemTime(&CurrentTime);

    RtlTimeToSecondsSince1970(&CurrentTime, &ulRet);

    return ulRet;
}


void StringToLUID(wchar_t * rule_text, PLARGE_INTEGER pli)
{
    wchar_t HighPart[32] = {0};
    wchar_t LowPart[32] = {0};
    ULONG High = 0;
    ULONG Low = 0;

    RtlStringCchCopyW(HighPart, _ARRAYSIZE(HighPart), L"0x");
    RtlCopyMemory(&HighPart[2], rule_text, 16);
    StringToInteger(HighPart, &High);

    RtlStringCchCopyW(LowPart, _ARRAYSIZE(LowPart), L"0x");
    RtlCopyMemory(&LowPart[2], &rule_text[8], 16);
    StringToInteger(LowPart, &Low);

    pli->HighPart = High;
    pli->LowPart = Low;
}


NTSTATUS CopyUnicodeString(_Inout_ PUNICODE_STRING DestString, _In_ PCUNICODE_STRING SourceString)
/*++
Routine Description:
    Captures a unicode string.
    The buffer is captured based on SourceString's Length field with the addition of sizeof(WCHAR) bytes for a NULL to signal the end of the string.
    Use FreeCapturedUnicodeString to free the captured string.
Arguments:
    DestString - Pointer to the unicode string that will receive the captured buffer.
    SourceString - Pointer tot he unicode string to be captured.
Return Value:
    NTSTATUS
--*/
/*
功能：复制一个字符串。
特色：目标字符串的地址不需要调用者申请。相比于RtlCopyUnicodeString。
注意：如果调用成功，目标字符串的内存需要调用者（如调用FreeUnicodeString函数）释放。

修改自：Windows-driver-samples\general\registry\regfltr\sys\capture.c的CaptureUnicodeString函数。
*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (NULL == DestString || NULL == SourceString) {
        return STATUS_INVALID_PARAMETER;
    }

    if (SourceString->Length == 0) {
        DestString->Length = 0;
        DestString->Buffer = NULL;
        DestString->MaximumLength = 0;
        return Status;
    }

    // Only SourceString->Length should be checked.
    // The registry does not validate SourceString->MaximumLength.
    //
    // An additional sizeof(WCHAR) bytes are added to the buffer size since
    // SourceString->Length does not include the NULL at the end of the string.

    DestString->Length = SourceString->Length;
    DestString->MaximumLength = SourceString->Length + sizeof(WCHAR);
    DestString->Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, DestString->MaximumLength, TAG);
    if (DestString->Buffer != NULL) {
        // It's a good practice to keep the contents of a try-except block to the bare minimum. 
        // By keeping the pool allocation call outside of the try-except block we don't mask possible pool corruptions.
        __try {
            RtlZeroMemory(DestString->Buffer, DestString->MaximumLength);
            RtlCopyMemory(DestString->Buffer, SourceString->Buffer, SourceString->Length);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error:%s", "Capturing Unicode String failed with exception");
            ExFreePoolWithTag(DestString->Buffer, TAG);
            DestString->Buffer = NULL;
            Status = GetExceptionCode();
        }
    } else {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error:%s", "Capturing Unicode String failed wtih insufficient resources");
        Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    if (DestString->Buffer == NULL) {
        DestString->Length = 0;
        DestString->MaximumLength = 0;
    }

    return Status;
}
