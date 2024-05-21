#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


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


VOID PrintVolume(__in PCFLT_RELATED_OBJECTS FltObjects);
NTSTATUS EnumerateFilters();


//////////////////////////////////////////////////////////////////////////////////////////////////
