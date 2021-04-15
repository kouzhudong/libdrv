#pragma once


#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct _GetUserFunctionAddressInfo {
    WCHAR DllFullName[MAX_PATH];
    CHAR FunctionName[MAX_PATH];
    PVOID UserFunctionAddress;
} GetUserFunctionAddressInfo, * PGetUserFunctionAddressInfo;


//////////////////////////////////////////////////////////////////////////////////////////////////


//WindowsResearchKernel-WRK\WRK-v1.2\public\sdk\inc\ntrtl.h
EXTERN_C
//NTSYSAPI 
PIMAGE_NT_HEADERS 
NTAPI RtlImageNtHeader(PVOID Base);


EXTERN_C PVOID RtlImageDirectoryEntryToData(IN PVOID Base,
                                            IN BOOLEAN MappedAsImage,
                                            IN USHORT DirectoryEntry,
                                            OUT PULONG Size);


EXTERN_C
//NTSYSAPI
NTSTATUS
NTAPI
LdrFindResource_U(
    IN PVOID DllHandle,
    IN CONST ULONG_PTR * ResourceIdPath,
    IN ULONG ResourceIdPathLength,
    OUT PIMAGE_RESOURCE_DATA_ENTRY * ResourceDataEntry
);


EXTERN_C
//NTSYSAPI
NTSTATUS
NTAPI
LdrAccessResource(
    IN PVOID DllHandle,
    IN CONST IMAGE_RESOURCE_DATA_ENTRY * ResourceDataEntry,
    OUT PVOID * Address OPTIONAL,
    OUT PULONG Size OPTIONAL
);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


PVOID MiFindExportedRoutineByName(_In_ PVOID DllBase, _In_ PANSI_STRING AnsiImageRoutineName);
PVOID MiFindExportedRoutineByNameEx(_In_ PVOID DllBase, _In_ PANSI_STRING AnsiImageRoutineName);
PVOID GetUserFunctionAddress(_In_ HANDLE ProcessId, _In_ PWSTR DllFullName, _In_ PSTR FunctionName);
BOOL IsPe64(_In_ PVOID ImageBase);
VOID ModifyPeEntry(_In_ PVOID ImageBase);
BOOL IsFilePe64(_In_ PUNICODE_STRING ImageFileName);
BOOL IsProcessPe64(_In_ HANDLE UniqueProcess);


EXTERN_C_END
