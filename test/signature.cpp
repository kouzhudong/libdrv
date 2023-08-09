#include "pch.h"
#include "signature.h"


void TestEcdsaSignature()
/*
功能：签名和验签的测试。

注意：
1.驱动竟然没有BCRYPT_DSA_ALGORITHM的算法，返回STATUS_NOT_FOUND。
2.BCRYPT_ECDSA_P256_ALGORITHM倒是在驱动下支持。
3.

心得：
1.在驱动下竟然可以使用BCRYPT_SHA512_ALGORITHM。
2.签名的算法不能是BCRYPT_RSA_ALGORITHM和BCRYPT_RSA_SIGN_ALGORITHM。
3.签名算法测试成功的有BCRYPT_DSA_ALGORITHM（3072和2048失败）和BCRYPT_ECDSA_P256_ALGORITHM。

参考：
1.https://docs.microsoft.com/zh-cn/windows/win32/seccng/signing-data-with-cng
2.Windows-classic-samples\Samples\Security\SignHashAndVerifySignature
3.ProcessHacker
*/
{
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    LPCWSTR AlgId = BCRYPT_ECDSA_P521_ALGORITHM;
    LPCWSTR Implementation = nullptr;
    ULONG   Flags = 0;
    NTSTATUS NtStatus = BCryptOpenAlgorithmProvider(&hAlgorithm, AlgId, Implementation, Flags);
    if (STATUS_SUCCESS != NtStatus) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", NtStatus);
        return;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    ULONG   Length = 521;
    NtStatus = BCryptGenerateKeyPair(hAlgorithm, &hKey, Length, 0);
    if (STATUS_SUCCESS != NtStatus) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return;
    }

    //NtStatus = BCryptSetProperty

    NtStatus = BCryptFinalizeKeyPair(hKey, 0);//这个还是很费时的。
    ASSERT(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PrivateKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &PrivateKeyLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    PBCRYPT_DSA_KEY_BLOB PrivateKey = (PBCRYPT_DSA_KEY_BLOB)ExAllocatePoolWithTag(NonPagedPool, PrivateKeyLen, TAG);
    ASSERT(PrivateKey);

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, (PUCHAR)PrivateKey, PrivateKeyLen, &PrivateKeyLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PublicKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &PublicKeyLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    PBCRYPT_DSA_KEY_BLOB PublicKey = (PBCRYPT_DSA_KEY_BLOB)ExAllocatePoolWithTag(NonPagedPool, PublicKeyLen, TAG);
    ASSERT(PublicKey);

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, (PUCHAR)PublicKey, PublicKeyLen, &PublicKeyLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    const char * Data = "test";
    ULONG DataSize = (ULONG)strlen(Data);

    PUCHAR Sign = nullptr;
    ULONG SignSize = 0;

    EcdsaSignHash((PUCHAR)PrivateKey, PrivateKeyLen, (PUCHAR)Data, DataSize, &Sign, &SignSize);

    EcdsaVerifySignature((PUCHAR)PublicKey, PublicKeyLen, (PUCHAR)Data, DataSize, Sign, SignSize);

    ExFreePoolWithTag(Sign, TAG);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ExFreePoolWithTag(PublicKey, TAG);
    ExFreePoolWithTag(PrivateKey, TAG);

    NtStatus = BCryptDestroyKey(hKey);
    NtStatus = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}
