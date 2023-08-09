#pragma once

#include "pch.h"


EXTERN_C_START


NTSTATUS WINAPI RsaPrivateKeyDecrypt(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                                     _In_ ULONG PrivateKeyLen,
                                     _In_reads_bytes_opt_(CipherTextSize) PUCHAR CipherText,
                                     _In_ ULONG CipherTextSize,
                                     _Out_writes_bytes_opt_(PlainTextSize) PUCHAR PlainText,
                                     _In_ ULONG PlainTextSize
);

NTSTATUS WINAPI RsaPublicKeyEncrypt(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                                    _In_ ULONG PublicKeyLen,
                                    _In_reads_bytes_opt_(PlainTextSize) PUCHAR PlainText,
                                    _In_ ULONG PlainTextSize,
                                    _Out_writes_bytes_opt_(CipherTextSize) PUCHAR CipherText,
                                    _In_ ULONG CipherTextSize
);


EXTERN_C_END


class encrypt
{

};
