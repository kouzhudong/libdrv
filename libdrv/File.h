#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
XP下运行要用XP编译环境。
并且添加如下代码。
先运行个FILEMON，也是获取到的为空。
*/
#if (NTDDI_VERSION < NTDDI_WS03SP1)
NTSTATUS IoEnumerateRegisteredFiltersList(IN PDRIVER_OBJECT * DriverObjectList, IN ULONG  DriverObjectListSize, OUT PULONG  ActualNumberDriverObjects);
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


NTSTATUS ZwEnumerateFile(IN UNICODE_STRING * directory);
NTSTATUS ZwEnumerateFileEx(IN UNICODE_STRING * directory);

VOID NTAPI WriteDiskSector(INT DiskIndex, LONGLONG StartingOffset, PVOID Buffer, ULONG Length);
VOID NTAPI ReadMBR(IN PDEVICE_OBJECT DeviceObject, IN ULONG SectorSize, OUT PVOID * Buffer);

#if (NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS IoReplaceFileObjectName(_In_ PFILE_OBJECT FileObject, _In_reads_bytes_(FileNameLength) PWSTR NewFileName, _In_ USHORT FileNameLength);
#endif


NTSTATUS ZwGetDosFileName(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, OUT PUNICODE_STRING DosFileName);

NTSTATUS ZwCreateHardLink(__in PUNICODE_STRING HardLinkFileName, __in PUNICODE_STRING  ExistingFileName);


EXTERN_C_END
