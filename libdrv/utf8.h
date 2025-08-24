#pragma once
#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


#if (NTDDI_VERSION < NTDDI_WIN7)
unsigned char * UnicodeToUTF8(int unicode, unsigned char * p);
int UTF8ToUnicode(unsigned char * ch, int * unicode);
#endif


#if (NTDDI_VERSION < NTDDI_WIN7)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSYSAPI NTSTATUS NTAPI RtlUnicodeToUTF8N(
    _Out_writes_bytes_to_(UTF8StringMaxByteCount, *UTF8StringActualByteCount) PCHAR UTF8StringDestination,
    _In_ ULONG UTF8StringMaxByteCount,
    _Out_ PULONG UTF8StringActualByteCount,
    _In_reads_bytes_(UnicodeStringByteCount) PCWCH UnicodeStringSource,
    _In_ ULONG UnicodeStringByteCount);
#endif

#if (NTDDI_VERSION < NTDDI_WIN7)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSYSAPI NTSTATUS NTAPI RtlUTF8ToUnicodeN(
    _Out_writes_bytes_to_(UnicodeStringMaxByteCount, *UnicodeStringActualByteCount) PWSTR UnicodeStringDestination,
    _In_ ULONG UnicodeStringMaxByteCount,
    _Out_ PULONG UnicodeStringActualByteCount,
    _In_reads_bytes_(UTF8StringByteCount) PCCH UTF8StringSource,
    _In_ ULONG UTF8StringByteCount);
#endif

#if (NTDDI_VERSION < NTDDI_WIN10_VB)
_When_(AllocateDestinationString, _At_(DestinationString->MaximumLength, _Out_range_(<=, (SourceString->MaximumLength / sizeof(WCHAR)))))
_When_(!AllocateDestinationString, _At_(DestinationString->Buffer, _Const_) _At_(DestinationString->MaximumLength, _Const_))
_IRQL_requires_max_(PASSIVE_LEVEL) _When_(AllocateDestinationString, _Must_inspect_result_)
//NTSYSAPI
NTSTATUS NTAPI RtlUnicodeStringToUTF8String(
    _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem))) 
        _When_(!AllocateDestinationString, _Inout_) PUTF8_STRING DestinationString,
    _In_ PCUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString);

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
//NTSYSAPI
NTSTATUS NTAPI RtlUTF8StringToUnicodeString(
    _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem)))
        _When_(!AllocateDestinationString, _Inout_) PUNICODE_STRING DestinationString,
    _In_ PUTF8_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString);
#endif


EXTERN_C_END