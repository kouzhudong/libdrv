#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_same_
_Success_(return == STATUS_SUCCESS)
NTSTATUS Sleep(_In_ UINT32 numMS);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN RtlIsNameInExpression(_In_ PUNICODE_STRING Expression, _In_ PUNICODE_STRING Name);

NTSTATUS AllocateUnicodeString(_In_ PUNICODE_STRING String);
VOID FreeUnicodeString(_In_ PUNICODE_STRING String);

LONG ExceptionFilter(_In_ PEXCEPTION_POINTERS ExceptionPointer);

void ConvertFormatTimeToSystemTime(IN wchar_t * rule_text, OUT PLARGE_INTEGER st);
void ConvertSystemTimeToFormatTime(IN PLARGE_INTEGER st, OUT PUNICODE_STRING pus);
ULONG GetCurrnetTime();

void StringToInteger(wchar_t * rule_text, PULONG y);
void StringToLUID(wchar_t * rule_text, PLARGE_INTEGER pli);


EXTERN_C_END
