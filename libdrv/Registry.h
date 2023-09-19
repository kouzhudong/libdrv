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
NTSTATUS SetValueKeyDword(_In_ PUNICODE_STRING KeyPath, _In_ PUNICODE_STRING ValueName, _In_ ULONG Value);
NTSTATUS GetKeyFullName(__in PVOID RootObject,
                        __in PUNICODE_STRING CompleteName,
                        _Inout_ PUNICODE_STRING KeyFullName
);


EXTERN_C_END
