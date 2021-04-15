#pragma once


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C NTSTATUS ZwUnloadKey(IN POBJECT_ATTRIBUTES KeyObjectAttributes);

EXTERN_C NTSTATUS ZwLoadKey(IN POBJECT_ATTRIBUTES KeyObjectAttributes,
                            IN POBJECT_ATTRIBUTES FileObjectAttributes);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


NTSTATUS ZwEnumerateKeyEx(IN UNICODE_STRING * Name);
NTSTATUS ZwCopyKey(IN UNICODE_STRING * Name, IN UNICODE_STRING * Name2);
NTSTATUS ZwCreateRootKey(_In_ POBJECT_ATTRIBUTES RegisterKey, _In_ POBJECT_ATTRIBUTES HiveFile);
NTSTATUS GetKeyFullName(_In_ PREG_CREATE_KEY_INFORMATION Info, _Inout_ PUNICODE_STRING FullKeyName);


EXTERN_C_END
