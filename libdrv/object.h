#pragma once


//////////////////////////////////////////////////////////////////////////////////////////////////


extern POBJECT_TYPE * IoDriverObjectType;
extern POBJECT_TYPE * IoDeviceObjectType;


EXTERN_C
//NTKERNELAPI
NTSTATUS ObReferenceObjectByName(
    IN PUNICODE_STRING ObjectName,
    IN ULONG Attributes,
    IN PACCESS_STATE PassedAccessState OPTIONAL,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    IN POBJECT_TYPE ObjectType OPTIONAL,
    IN KPROCESSOR_MODE AccessMode,
    IN OUT PVOID ParseContext OPTIONAL,
    OUT PVOID * Object);


//WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\inc\ob.h
//EXTERN_C
////NTKERNELAPI
//NTSTATUS
//ObOpenObjectByName(
//    __in POBJECT_ATTRIBUTES ObjectAttributes,
//    __in_opt POBJECT_TYPE ObjectType,
//    __in KPROCESSOR_MODE AccessMode,
//    __inout_opt PACCESS_STATE AccessState,
//    __in_opt ACCESS_MASK DesiredAccess,
//    __inout_opt PVOID ParseContext,
//    __out PHANDLE Handle);

/*
Opens an object with full access validation and auditing.

看看更新日期：03/21/2023

Remarks
This function is not defined in an SDK header and must be declared by the caller. 
This function is exported from ntoskrnl.exe.

https://learn.microsoft.com/en-us/windows/win32/devnotes/obopenobjectbyname-function
*/
EXTERN_C NTSTATUS ObOpenObjectByName(
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __in POBJECT_TYPE ObjectType, //必须填写，否则蓝屏。
    __in KPROCESSOR_MODE AccessMode,
    __inout_opt PACCESS_STATE AccessState,
    __in_opt ACCESS_MASK DesiredAccess,
    __inout_opt PVOID ParseContext,
    __out PHANDLE Handle);


//https://learn.microsoft.com/en-us/windows/win32/devnotes/obopenobjectbyname-function
//typedef struct _OBJECT_TYPE
//{
//    LIST_ENTRY TypeList;
//    UNICODE_STRING Name;
//    PVOID DefaultObject;
//    UCHAR Index;
//    __volatile ULONG TotalNumberOfObjects;
//    __volatile ULONG TotalNumberOfHandles;
//    ULONG HighWaterNumberOfObjects;
//    ULONG HighWaterNumberOfHandles;
//    OBJECT_TYPE_INITIALIZER TypeInfo;//这个需要定义。
//    EX_PUSH_LOCK TypeLock;
//    ULONG Key;
//} OBJECT_TYPE, * POBJECT_TYPE;


//幸甚：\Windows Kits\10\Include\10.0.19041.0\km\ntifs.h已经有定义了
//EXTERN_C
//NTSTATUS ZwOpenDirectoryObject(
//    __out  PHANDLE DirectoryHandle,
//    __in   ACCESS_MASK DesiredAccess,
//    __in   POBJECT_ATTRIBUTES ObjectAttributes);


//\WRK-v1.2\public\internal\base\inc\zwapi.h
//https://msdn.microsoft.com/en-us/library/bb470238(v=vs.85).aspx
EXTERN_C
//NTSYSAPI
NTSTATUS NTAPI ZwQueryDirectoryObject(
    __in HANDLE DirectoryHandle,
    __out_bcount_opt(Length) PVOID Buffer,
    __in ULONG Length,
    __in BOOLEAN ReturnSingleEntry,
    __in BOOLEAN RestartScan,
    __inout PULONG Context,
    __out_opt PULONG ReturnLength);


//\WRK-v1.2\public\sdk\inc\ntobapi.h
//https://msdn.microsoft.com/en-us/library/bb470238(v=vs.85).aspx
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;


//摘自：\wrk\WindowsResearchKernel-WRK\WRK-v1.2\public\sdk\inc\ntexapi.h
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;


//摘自：\wrk\WindowsResearchKernel-WRK\WRK-v1.2\public\sdk\inc\ntexapi.h
typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


NTSTATUS GetObjectNtName(_In_ PVOID Object, _Inout_ PUNICODE_STRING NtName);
NTSTATUS GetObjectName(_In_ PVOID Object, _Inout_ PUNICODE_STRING ObjectName);
NTSTATUS GetFileObjectDosName(_In_ PFILE_OBJECT FileObject, _Inout_ PUNICODE_STRING DosName);

void GetKnownDllPath();
void GetKnownDllPathEx();
void GetSystemRootPathName(PUNICODE_STRING PathName, PUNICODE_STRING NtPathName, PUNICODE_STRING DosPathName);

NTSTATUS GetSystemRootName(_In_ PUNICODE_STRING SymbolicLinkName, _Inout_ PUNICODE_STRING NtPathName, _Inout_ PUNICODE_STRING DosPathName);

NTSTATUS ZwEnumerateObject(_In_ PUNICODE_STRING Directory);
NTSTATUS ZwEnumerateDriverObject();

#if (NTDDI_VERSION >= NTDDI_VISTA)
void EnumerateTransactionObject();
#endif


NTSTATUS ZwQueryObjectNameByHandle(IN HANDLE Handle, OUT PUNICODE_STRING ObjectName);
NTSTATUS EnumerateProcessHandles(IN HANDLE pid, OUT PDWORD ProcessHandles);


EXTERN_C_END
