#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
XP下运行要用XP编译环境。
并且添加如下代码。
先运行个FILEMON，也是获取到的为空。
*/
#if (NTDDI_VERSION < NTDDI_WS03SP1)
NTSTATUS
IoEnumerateRegisteredFiltersList(
    IN PDRIVER_OBJECT * DriverObjectList,
    IN ULONG  DriverObjectListSize,
    OUT PULONG  ActualNumberDriverObjects
);
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


NTSTATUS ZwEnumerateFile(IN UNICODE_STRING * directory);
NTSTATUS ZwEnumerateFileEx(IN UNICODE_STRING * directory);

NTSTATUS FltGetFileNameInformationEx(__inout PFLT_CALLBACK_DATA Cbd,
                                     __in PCFLT_RELATED_OBJECTS FltObjects,
                                     OUT PUNICODE_STRING usFullPath);

#if (NTDDI_VERSION < NTDDI_VISTA)
NTSTATUS FltQueryDirectoryFile( //FltQueryDirectoryFile_XP 为XP量身打造的FltQueryDirectoryFile
                               _In_ PFLT_INSTANCE Instance,
                               _In_ PFILE_OBJECT FileObject,
                               _Out_writes_bytes_(Length) PVOID FileInformationBuffer,
                               _In_ ULONG Length,
                               _In_ FILE_INFORMATION_CLASS FileInformationClass,
                               _In_ BOOLEAN ReturnSingleEntry,
                               _In_opt_ PUNICODE_STRING FileName,
                               _In_ BOOLEAN RestartScan,
                               _Out_opt_ PULONG LengthReturned
);
#endif

#if (NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS IoReplaceFileObjectName(_In_ PFILE_OBJECT FileObject,
                                 _In_reads_bytes_(FileNameLength) PWSTR NewFileName,
                                 _In_ USHORT FileNameLength);
#endif

VOID PrintVolume(__in PCFLT_RELATED_OBJECTS FltObjects);

NTSTATUS ZwGetDosFileName(_Inout_ PFLT_CALLBACK_DATA Data,
                          _In_ PCFLT_RELATED_OBJECTS FltObjects,
                          OUT PUNICODE_STRING DosFileName);

NTSTATUS ZwCreateHardLink(__in PUNICODE_STRING HardLinkFileName, __in PUNICODE_STRING  ExistingFileName);

NTSTATUS EnumerateFilters();


EXTERN_C_END
