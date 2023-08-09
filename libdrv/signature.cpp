#include "signature.h"
#include "hash.h"


NTSTATUS WINAPI EcdsaSignHash(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                              _In_ ULONG PrivateKeyLen,
                              _In_reads_bytes_(DataSize) PUCHAR Data,
                              _In_ ULONG DataSize,
                              _Out_writes_bytes_all_(*SignSize) PUCHAR * Sign,
                              _In_ ULONG * SignSize
)
{
    PUCHAR Hash = nullptr;
    ULONG HashSize = 0;
    BOOL ret = CngHashData(BCRYPT_SHA1_ALGORITHM, Data, DataSize, &Hash, &HashSize);
    ASSERT(ret);

    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE       hSignAlg = NULL;
    status = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_ECDSA_P521_ALGORITHM, NULL, 0);
    ASSERT(NT_SUCCESS(status));

    BCRYPT_KEY_HANDLE hPrivateKey = NULL;
    status = BCryptImportKeyPair(hSignAlg,
                                 NULL,
                                 BCRYPT_ECCPRIVATE_BLOB,
                                 &hPrivateKey,
                                 PrivateKey,
                                 PrivateKeyLen,
                                 BCRYPT_NO_KEY_VALIDATION);
    ASSERT(NT_SUCCESS(status));

    status = BCryptSignHash(hPrivateKey, NULL, Hash, HashSize, NULL, 0, SignSize, 0);
    ASSERT(NT_SUCCESS(status));

    *Sign = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, *SignSize, TAG);
    ASSERT(*Sign);

    ULONG Result = 0;
    status = BCryptSignHash(hPrivateKey, NULL, Hash, HashSize, *Sign, *SignSize, &Result, 0);
    ASSERT(NT_SUCCESS(status));

    BCryptCloseAlgorithmProvider(hSignAlg, 0);
    BCryptDestroyKey(hPrivateKey);

    return status;
}


BOOL WINAPI EcdsaVerifySignature(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                                 _In_ ULONG PublicKeyLen,
                                 _In_reads_bytes_(DataSize) PUCHAR Data,
                                 _In_ ULONG DataSize,
                                 _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                                 _In_ ULONG SignSize
)
{
    PUCHAR Hash = nullptr;
    ULONG HashSize = 0;
    BOOL IsVerify = FALSE;
    BOOL ret = CngHashData(BCRYPT_SHA1_ALGORITHM, Data, DataSize, &Hash, &HashSize);
    ASSERT(ret);

    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE       hSignAlg = NULL;
    status = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_ECDSA_P521_ALGORITHM, NULL, 0);
    ASSERT(NT_SUCCESS(status));

    BCRYPT_KEY_HANDLE hPublicKey = NULL;
    status = BCryptImportKeyPair(hSignAlg,
                                 NULL,
                                 BCRYPT_ECCPUBLIC_BLOB,
                                 &hPublicKey,
                                 PublicKey,
                                 PublicKeyLen,
                                 BCRYPT_NO_KEY_VALIDATION);
    ASSERT(NT_SUCCESS(status));

    status = BCryptVerifySignature(hPublicKey, NULL, Hash, HashSize, Sign, SignSize, 0);
    if (NT_SUCCESS(status)) {
        IsVerify = TRUE;
    }

    BCryptCloseAlgorithmProvider(hSignAlg, 0);
    BCryptDestroyKey(hPublicKey);

    return IsVerify;
}
