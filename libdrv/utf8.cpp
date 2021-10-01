#include "utf8.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#if (NTDDI_VERSION < NTDDI_WIN7)


unsigned char * UnicodeToUTF8(int unicode, unsigned char * p)
/**ժ�ԣ����磬�д����ԡ�
 * UnicodeToUTF8 - convert unicode char to UTF-8 char
 * @unicode: a UNICODE(utf-16) character
 * @p: a buffer to contain a utf-8 characters
 *
 * @return: One step over the end of the utf-8 character buffer
 */
{
    unsigned char * e = NULL;

    if ((e = p)) {
        if (unicode < 0x80) {
            *e++ = unicode;
        } else if (unicode < 0x800) {
            /* <11011111> < 000 0000 0000> */
            *e++ = ((unicode >> 6) & 0x1f) | 0xc0;
            *e++ = (unicode & 0x3f) | 0x80;
        } else if (unicode < 0x10000) {
            /* <11101111> <0000 0000 0000 0000> */
            *e++ = ((unicode >> 12) & 0x0f) | 0xe0;
            *e++ = ((unicode >> 6) & 0x3f) | 0x80;
            *e++ = (unicode & 0x3f) | 0x80;
        } else if (unicode < 0x200000) {
            /* <11110111> <0 0000 0000 0000 0000 0000> */
            *e++ = ((unicode >> 18) & 0x07) | 0xf0;
            *e++ = ((unicode >> 12) & 0x3f) | 0x80;
            *e++ = ((unicode >> 6) & 0x3f) | 0x80;
            *e++ = (unicode & 0x3f) | 0x80;
        } else if (unicode < 0x4000000) {
            /* <11111011> <00 0000 0000 0000 0000 0000 0000> */
            *e++ = ((unicode >> 24) & 0x03) | 0xf8;
            *e++ = ((unicode >> 18) & 0x3f) | 0x80;
            *e++ = ((unicode >> 12) & 0x3f) | 0x80;
            *e++ = ((unicode >> 6) & 0x3f) | 0x80;
            *e++ = (unicode & 0x3f) | 0x80;
        } else {
            /* <11111101> <0000 0000 0000 0000 0000 0000 0000 0000> */
            *e++ = ((unicode >> 30) & 0x01) | 0xfc;
            *e++ = ((unicode >> 24) & 0x3f) | 0x80;
            *e++ = ((unicode >> 18) & 0x3f) | 0x80;
            *e++ = ((unicode >> 12) & 0x3f) | 0x80;
            *e++ = ((unicode >> 6) & 0x3f) | 0x80;
            *e++ = (unicode & 0x3f) | 0x80;
        }
    }

    /* Return One step over the end of the utf-8 character buffer */
    return e;
}


int UTF8ToUnicode(unsigned char * ch, int * unicode)
/**ժ�ԣ����磬�д����ԡ�
 * UTF8ToUnicode - convert UTF-8 char to unicode char
 * @ch: A buffer contain a utf-8 character
 * @unicode: Contain the converted utf-16 character
 *
 * @return: Bytes count of the utf-8 character (1 ~ 6),
 *          can be used to step to next utf-8 character when convert a utf-8 string to a utf-16 string
 */
{
    unsigned char * p = NULL;
    int e = 0, n = 0;

    if ((p = ch) && unicode) {
        if (*p >= 0xfc) {
            /* 6:<11111100> */
            e = (p[0] & 0x01) << 30;
            e |= (p[1] & 0x3f) << 24;
            e |= (p[2] & 0x3f) << 18;
            e |= (p[3] & 0x3f) << 12;
            e |= (p[4] & 0x3f) << 6;
            e |= (p[5] & 0x3f);
            n = 6;
        } else if (*p >= 0xf8) {
            /* 5:<11111000> */
            e = (p[0] & 0x03) << 24;
            e |= (p[1] & 0x3f) << 18;
            e |= (p[2] & 0x3f) << 12;
            e |= (p[3] & 0x3f) << 6;
            e |= (p[4] & 0x3f);
            n = 5;
        } else if (*p >= 0xf0) {
            /* 4:<11110000> */
            e = (p[0] & 0x07) << 18;
            e |= (p[1] & 0x3f) << 12;
            e |= (p[2] & 0x3f) << 6;
            e |= (p[3] & 0x3f);
            n = 4;
        } else if (*p >= 0xe0) {
            /* 3:<11100000> */
            e = (p[0] & 0x0f) << 12;
            e |= (p[1] & 0x3f) << 6;
            e |= (p[2] & 0x3f);
            n = 3;
        } else if (*p >= 0xc0) {
            /* 2:<11000000> */
            e = (p[0] & 0x1f) << 6;
            e |= (p[1] & 0x3f);
            n = 2;
        } else {
            e = p[0];
            n = 1;
        }

        *unicode = e;
    }

    /* Return bytes count of this utf-8 character */
    return n;
}


#endif


#if (NTDDI_VERSION < NTDDI_WIN7)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
//NTSYSAPI
NTSTATUS
NTAPI
RtlUnicodeToUTF8N(
    _Out_writes_bytes_to_(UTF8StringMaxByteCount, *UTF8StringActualByteCount) PCHAR  UTF8StringDestination,
    _In_                                ULONG  UTF8StringMaxByteCount,
    _Out_                               PULONG UTF8StringActualByteCount,
    _In_reads_bytes_(UnicodeStringByteCount) PCWCH UnicodeStringSource,
    _In_                                ULONG  UnicodeStringByteCount
)
/*
����UnicodeToUTF8ʵ�֡�

ע�ͣ�һ���ַ���Unicodeռ�����ֽڣ�UTF8���ռ4�ֽڡ�
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(UTF8StringDestination);
    UNREFERENCED_PARAMETER(UTF8StringDestination);
    UNREFERENCED_PARAMETER(UTF8StringDestination);
    UNREFERENCED_PARAMETER(UTF8StringDestination);
    UNREFERENCED_PARAMETER(UTF8StringDestination);


    rturn status;
}
#endif


#if (NTDDI_VERSION < NTDDI_WIN7)
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
//NTSYSAPI
NTSTATUS
NTAPI
RtlUTF8ToUnicodeN(
    _Out_writes_bytes_to_(UnicodeStringMaxByteCount, *UnicodeStringActualByteCount) PWSTR  UnicodeStringDestination,
    _In_                             ULONG  UnicodeStringMaxByteCount,
    _Out_                            PULONG UnicodeStringActualByteCount,
    _In_reads_bytes_(UTF8StringByteCount) PCCH   UTF8StringSource,
    _In_                             ULONG  UTF8StringByteCount
)
/*
����UTF8ToUnicodeʵ�֡�

ע�ͣ�һ���ַ���Unicodeռ�����ֽڣ�UTF8���ռ4�ֽڡ�
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(UTF8StringDestination);
    UNREFERENCED_PARAMETER(UTF8StringDestination);
    UNREFERENCED_PARAMETER(UTF8StringDestination);
    UNREFERENCED_PARAMETER(UTF8StringDestination);
    UNREFERENCED_PARAMETER(UTF8StringDestination); 


    rturn status;
}
#endif


#if (NTDDI_VERSION < NTDDI_WIN10_VB)


_When_(AllocateDestinationString,
       _At_(DestinationString->MaximumLength,
            _Out_range_(<= , (SourceString->MaximumLength / sizeof(WCHAR)))))
    _When_(!AllocateDestinationString,
           _At_(DestinationString->Buffer, _Const_)
           _At_(DestinationString->MaximumLength, _Const_))
    _IRQL_requires_max_(PASSIVE_LEVEL)
    _When_(AllocateDestinationString, _Must_inspect_result_)
    //NTSYSAPI
    NTSTATUS
    NTAPI
    RtlUnicodeStringToUTF8String(
        _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem)))
        _When_(!AllocateDestinationString, _Inout_)
        PUTF8_STRING DestinationString,
        _In_ PCUNICODE_STRING SourceString,
        _In_ BOOLEAN AllocateDestinationString
    )
    /*
    ����RtlUnicodeToUTF8Nʵ�֡�
    */
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(DestinationString);
    UNREFERENCED_PARAMETER(SourceString);
    UNREFERENCED_PARAMETER(AllocateDestinationString);

    return status;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
//NTSYSAPI
NTSTATUS
NTAPI
RtlUTF8StringToUnicodeString(
    _When_(AllocateDestinationString, _Out_ _At_(DestinationString->Buffer, __drv_allocatesMem(Mem)))
    _When_(!AllocateDestinationString, _Inout_)
    PUNICODE_STRING DestinationString,
    _In_ PUTF8_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
)
/*
����RtlUTF8ToUnicodeNʵ�֡�
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(DestinationString);
    UNREFERENCED_PARAMETER(SourceString);
    UNREFERENCED_PARAMETER(AllocateDestinationString);

    return status;
}


#endif


//////////////////////////////////////////////////////////////////////////////////////////////////
