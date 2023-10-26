#include "signature.h"
#include "hash.h"


NTSTATUS WINAPI SignHash(_In_z_ LPCWSTR pszHashId,
                         _In_z_ LPCWSTR pszAlgId,
                         _In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                         _In_ ULONG PrivateKeyLen,
                         _In_reads_bytes_(DataSize) PUCHAR Data,
                         _In_ ULONG DataSize,
                         _Out_writes_bytes_all_(*SignSize) PUCHAR * Sign,
                         _In_ ULONG * SignSize
)
/*
参数越多，功能越强大。
*/
{
    PUCHAR Hash = nullptr;
    ULONG HashSize = 0;
    BOOL ret = CngHashData(pszHashId, Data, DataSize, &Hash, &HashSize);
    ASSERT(ret);

    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE       hSignAlg = nullptr;
    status = BCryptOpenAlgorithmProvider(&hSignAlg, pszAlgId, nullptr, 0);
    ASSERT(NT_SUCCESS(status));

    BCRYPT_KEY_HANDLE hPrivateKey = nullptr;
    status = BCryptImportKeyPair(hSignAlg,
                                 nullptr,
                                 BCRYPT_ECCPRIVATE_BLOB,
                                 &hPrivateKey,
                                 PrivateKey,
                                 PrivateKeyLen,
                                 BCRYPT_NO_KEY_VALIDATION);
    ASSERT(NT_SUCCESS(status));

    status = BCryptSignHash(hPrivateKey, nullptr, Hash, HashSize, nullptr, 0, SignSize, 0);
    ASSERT(NT_SUCCESS(status));

    *Sign = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPool, *SignSize, TAG));
    ASSERT(*Sign);

    ULONG Result = 0;
    status = BCryptSignHash(hPrivateKey, nullptr, Hash, HashSize, *Sign, *SignSize, &Result, 0);
    ASSERT(NT_SUCCESS(status));

    BCryptCloseAlgorithmProvider(hSignAlg, 0);
    BCryptDestroyKey(hPrivateKey);

    return status;
}


BOOL WINAPI VerifySignature(_In_z_ LPCWSTR pszHashId,
                            _In_z_ LPCWSTR pszAlgId,
                            _In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                            _In_ ULONG PublicKeyLen,
                            _In_reads_bytes_(DataSize) PUCHAR Data,
                            _In_ ULONG DataSize,
                            _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                            _In_ ULONG SignSize
)
/*
注意：不是所有的组合，Windows都支持。
*/
{
    PUCHAR Hash = nullptr;
    ULONG HashSize = 0;
    BOOL IsVerify = FALSE;
    BOOL ret = CngHashData(pszHashId, Data, DataSize, &Hash, &HashSize);
    ASSERT(ret);

    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    BCRYPT_ALG_HANDLE       hSignAlg = nullptr;
    status = BCryptOpenAlgorithmProvider(&hSignAlg, pszAlgId, nullptr, 0);
    ASSERT(NT_SUCCESS(status));

    BCRYPT_KEY_HANDLE hPublicKey = nullptr;
    status = BCryptImportKeyPair(hSignAlg,
                                 nullptr,
                                 BCRYPT_ECCPUBLIC_BLOB,
                                 &hPublicKey,
                                 PublicKey,
                                 PublicKeyLen,
                                 BCRYPT_NO_KEY_VALIDATION);
    ASSERT(NT_SUCCESS(status));

    status = BCryptVerifySignature(hPublicKey, nullptr, Hash, HashSize, Sign, SignSize, 0);
    if (NT_SUCCESS(status)) {
        IsVerify = TRUE;
    }

    BCryptCloseAlgorithmProvider(hSignAlg, 0);
    BCryptDestroyKey(hPublicKey);

    return IsVerify;
}



NTSTATUS WINAPI SignHashByEcdsa(_In_reads_bytes_(PrivateKeyLen) PUCHAR PrivateKey,
                                _In_ ULONG PrivateKeyLen,
                                _In_reads_bytes_(DataSize) PUCHAR Data,
                                _In_ ULONG DataSize,
                                _Out_writes_bytes_all_(*SignSize) PUCHAR * Sign,
                                _In_ ULONG * SignSize
)
{
    return SignHash(BCRYPT_SHA512_ALGORITHM,
                    BCRYPT_ECDSA_P521_ALGORITHM,
                    PrivateKey,
                    PrivateKeyLen,
                    Data,
                    DataSize,
                    Sign,
                    SignSize);
}


BOOL WINAPI VerifySignatureByEcdsa(_In_reads_bytes_(PublicKeyLen) PUCHAR PublicKey,
                                   _In_ ULONG PublicKeyLen,
                                   _In_reads_bytes_(DataSize) PUCHAR Data,
                                   _In_ ULONG DataSize,
                                   _Out_writes_bytes_all_(SignSize) PUCHAR Sign,
                                   _In_ ULONG SignSize
)
{
    return VerifySignature(BCRYPT_SHA512_ALGORITHM,
                           BCRYPT_ECDSA_P521_ALGORITHM,
                           PublicKey,
                           PublicKeyLen,
                           Data,
                           DataSize,
                           Sign,
                           SignSize);
}
