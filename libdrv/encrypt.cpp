#include "encrypt.h"


NTSTATUS WINAPI RsaPrivateKeyDecrypt(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                                     _In_ ULONG PrivateKeyLen,
                                     _In_reads_bytes_opt_(CipherTextSize) PUCHAR CipherText,
                                     _In_ ULONG CipherTextSize,
                                     _Out_writes_bytes_opt_(PlainTextSize) PUCHAR PlainText,
                                     _In_ ULONG PlainTextSize
)
/*

*/
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    __try {
        Status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = BCryptImportKeyPair(hAlgorithm,
                                     NULL,
                                     BCRYPT_RSAPRIVATE_BLOB,
                                     &hKey,
                                     PrivateKey,
                                     PrivateKeyLen,
                                     BCRYPT_NO_KEY_VALIDATION);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = BCryptDecrypt(hKey,
                               CipherText,
                               CipherTextSize,
                               NULL,
                               NULL,
                               0,
                               PlainText,
                               PlainTextSize,
                               &PlainTextSize,
                               BCRYPT_PAD_PKCS1);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }
    } __finally {
        if (hKey) {
            BCryptDestroyKey(hKey);
        }

        if (hAlgorithm) {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        }
    }

    return Status;
}



NTSTATUS WINAPI RsaPublicKeyEncrypt(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                                    _In_ ULONG PublicKeyLen,
                                    _In_reads_bytes_opt_(PlainTextSize) PUCHAR PlainText,
                                    _In_ ULONG PlainTextSize,
                                    _Out_writes_bytes_opt_(CipherTextSize) PUCHAR CipherText,
                                    _In_ ULONG CipherTextSize
)
/*


*/
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    BCRYPT_KEY_HANDLE hKey = NULL;

    __try {
        Status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = BCryptImportKeyPair(hAlgorithm,
                                     NULL,
                                     BCRYPT_RSAPUBLIC_BLOB,
                                     &hKey,
                                     PublicKey,
                                     PublicKeyLen,
                                     BCRYPT_NO_KEY_VALIDATION);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = BCryptEncrypt(hKey,
                               PlainText,
                               PlainTextSize,
                               NULL,
                               NULL,
                               0,
                               CipherText,
                               CipherTextSize,
                               &CipherTextSize,
                               BCRYPT_PAD_PKCS1);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }
    } __finally {
        if (hKey) {
            BCryptDestroyKey(hKey);
        }

        if (hAlgorithm) {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        }
    }

    return Status;
}
