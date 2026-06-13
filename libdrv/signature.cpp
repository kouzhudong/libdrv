#include "signature.h"
#include "hash.h"


NTSTATUS WINAPI SignHash(_In_z_ LPCWSTR pszHashId,
                         _In_z_ LPCWSTR pszAlgId,
                         _In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                         _In_ ULONG PrivateKeyLen,
                         _In_reads_bytes_(DataSize) PUCHAR Data,
                         _In_ ULONG DataSize,
                         _Out_writes_bytes_all_(*SignSize) PUCHAR * Sign,
                         _In_ ULONG * SignSize)
{
    PUCHAR Hash = nullptr;
    ULONG HashSize = 0;
    BCRYPT_ALG_HANDLE hSignAlg = nullptr;
    BCRYPT_KEY_HANDLE hPrivateKey = nullptr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    __try {
        BOOL ret = CngHashData(pszHashId, Data, DataSize, &Hash, &HashSize);
        if (!ret) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "CngHashData failed");
            __leave;
        }

        status = BCryptOpenAlgorithmProvider(&hSignAlg, pszAlgId, nullptr, 0);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", status);
            __leave;
        }

        status = BCryptImportKeyPair(hSignAlg, nullptr, BCRYPT_ECCPRIVATE_BLOB, &hPrivateKey, PrivateKey, PrivateKeyLen, BCRYPT_NO_KEY_VALIDATION);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", status);
            __leave;
        }

        status = BCryptSignHash(hPrivateKey, nullptr, Hash, HashSize, nullptr, 0, SignSize, 0);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", status);
            __leave;
        }

        *Sign = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPool, *SignSize, TAG));
        if (!*Sign) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", status);
            __leave;
        }
        RtlZeroMemory(*Sign, *SignSize);
        ULONG Result = 0;
        status = BCryptSignHash(hPrivateKey, nullptr, Hash, HashSize, *Sign, *SignSize, &Result, 0);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", status);
            ExFreePoolWithTag(*Sign, TAG);
            *Sign = nullptr;
        }
    } __finally {
        if (hPrivateKey) {
            BCryptDestroyKey(hPrivateKey);
        }
        if (hSignAlg) {
            BCryptCloseAlgorithmProvider(hSignAlg, 0);
        }
        if (Hash) {
            ExFreePoolWithTag(Hash, TAG);
        }
    }

    return status;
}


BOOL WINAPI VerifySignature(_In_z_ LPCWSTR pszHashId,
                            _In_z_ LPCWSTR pszAlgId,
                            _In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                            _In_ ULONG PublicKeyLen,
                            _In_reads_bytes_(DataSize) PUCHAR Data,
                            _In_ ULONG DataSize,
                            _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                            _In_ ULONG SignSize)
{
    PUCHAR Hash = nullptr;
    ULONG HashSize = 0;
    BOOL IsVerify = FALSE;
    BCRYPT_ALG_HANDLE hSignAlg = nullptr;
    BCRYPT_KEY_HANDLE hPublicKey = nullptr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    __try {
        BOOL ret = CngHashData(pszHashId, Data, DataSize, &Hash, &HashSize);
        if (!ret) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "CngHashData failed");
            __leave;
        }

        status = BCryptOpenAlgorithmProvider(&hSignAlg, pszAlgId, nullptr, 0);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", status);
            __leave;
        }

        status = BCryptImportKeyPair(hSignAlg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &hPublicKey, PublicKey, PublicKeyLen, BCRYPT_NO_KEY_VALIDATION);
        if (!NT_SUCCESS(status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", status);
            __leave;
        }

        status = BCryptVerifySignature(hPublicKey, nullptr, Hash, HashSize, Sign, SignSize, 0);
        if (NT_SUCCESS(status)) {
            IsVerify = TRUE;
        }
    } __finally {
        if (hPublicKey) {
            BCryptDestroyKey(hPublicKey);
        }
        if (hSignAlg) {
            BCryptCloseAlgorithmProvider(hSignAlg, 0);
        }
        if (Hash) {
            ExFreePoolWithTag(Hash, TAG);
        }
    }

    return IsVerify;
}


NTSTATUS WINAPI SignHashByEcdsa(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                                _In_ ULONG PrivateKeyLen,
                                _In_reads_bytes_(DataSize) PUCHAR Data,
                                _In_ ULONG DataSize,
                                _Out_writes_bytes_all_(*SignSize) PUCHAR * Sign,
                                _In_ ULONG * SignSize)
{
    return SignHash(BCRYPT_SHA512_ALGORITHM, BCRYPT_ECDSA_P521_ALGORITHM, PrivateKey, PrivateKeyLen, Data, DataSize, Sign, SignSize);
}


BOOL WINAPI VerifySignatureByEcdsa(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                                   _In_ ULONG PublicKeyLen,
                                   _In_reads_bytes_(DataSize) PUCHAR Data,
                                   _In_ ULONG DataSize,
                                   _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                                   _In_ ULONG SignSize)
{
    return VerifySignature(BCRYPT_SHA512_ALGORITHM, BCRYPT_ECDSA_P521_ALGORITHM, PublicKey, PublicKeyLen, Data, DataSize, Sign, SignSize);
}
