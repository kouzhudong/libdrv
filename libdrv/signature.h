#pragma once

#include "pch.h"


EXTERN_C_START


NTSTATUS WINAPI SignHashByEcdsa(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                                _In_ ULONG PrivateKeyLen,
                                _In_reads_bytes_(DataSize) PUCHAR Data,
                                _In_ ULONG DataSize,
                                _Out_writes_bytes_all_(*SignSize) PUCHAR * Sign,
                                _In_ ULONG * SignSize
);

BOOL WINAPI VerifySignatureByEcdsa(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                                   _In_ ULONG PublicKeyLen,
                                   _In_reads_bytes_(DataSize) PUCHAR Data,
                                   _In_ ULONG DataSize,
                                   _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                                   _In_ ULONG SignSize
);


EXTERN_C_END
