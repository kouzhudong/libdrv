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
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING  DestinationString;
    BOOLEAN B;

    PAGED_CODE();

    if (Expression == 0 || Name == 0) {
        return FALSE;
    }

    status = RtlUpcaseUnicodeString(&DestinationString, Expression, TRUE);
    if (!NT_SUCCESS(status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL, "status:%#x", status);
        return FALSE;
    }

    B = FsRtlIsNameInExpression(&DestinationString, Name, TRUE, 0);

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
    if (String->Buffer == NULL) {
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
        String->Buffer = NULL;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}


LONG ExceptionFilter(_In_ PEXCEPTION_POINTERS ExceptionPointer)
/*++
Routine Description:
Exception filter to catch errors touching user buffers.

Arguments:
ExceptionPointer - The exception record.
AccessingUserBuffer - If TRUE, overrides FsRtlIsNtStatusExpected to allow the caller to munge the error to a desired status.

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
    TIME_FIELDS tf = {0};
    LARGE_INTEGER temp;
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
    TIME_FIELDS tf = {0};
    NTSTATUS status;

    RtlTimeToTimeFields(st, &tf);

    status = RtlStringCbPrintfW(TimeString->Buffer,
                                TimeString->MaximumLength,
                                L"%04d-%02d-%02d %02d:%02d:%02d",
                                tf.Year,
                                tf.Month,
                                tf.Day,
                                tf.Hour,
                                tf.Minute,
                                tf.Second);
    ASSERT(NT_SUCCESS(status));

    TimeString->Length = (USHORT)wcsnlen(TimeString->Buffer, TimeString->MaximumLength);
}


void StringToInteger(wchar_t * rule_text, PULONG y)
{
    NTSTATUS status;
    UNICODE_STRING rule = {0};

    RtlInitUnicodeString(&rule, rule_text);

    status = RtlUnicodeStringToInteger(&rule, 0, y);
    ASSERT(NT_SUCCESS(status));
}


ULONG GetCurrnetTime()
{
    ULONG ulRet = 0;
    LARGE_INTEGER CurrentTime = {0};

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
