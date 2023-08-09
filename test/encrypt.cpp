#include "pch.h"
#include "encrypt.h"


void TestRsaEncrypt()
{
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    LPCWSTR AlgId = BCRYPT_RSA_ALGORITHM;
    LPCWSTR Implementation = nullptr;
    ULONG   Flags = 0;
    NTSTATUS NtStatus = BCryptOpenAlgorithmProvider(&hAlgorithm, AlgId, Implementation, Flags);
    if (STATUS_SUCCESS != NtStatus) {

        return;
    }

    BCRYPT_KEY_HANDLE hKey = nullptr;
    ULONG   Length = 3072;//16384
    NtStatus = BCryptGenerateKeyPair(hAlgorithm, &hKey, Length, 0);
    if (STATUS_SUCCESS != NtStatus) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        return;
    }

    //NtStatus = BCryptSetProperty

    NtStatus = BCryptFinalizeKeyPair(hKey, 0);//这个还是很费时的，特别是16384时。
    ASSERT(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG KeyPairLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, 0, &KeyPairLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    BCRYPT_RSAKEY_BLOB * RsaKeyPair = (BCRYPT_RSAKEY_BLOB *)ExAllocatePoolWithTag(NonPagedPool, KeyPairLen, TAG);
    ASSERT(RsaKeyPair);//前四个字节是：RSA3

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, (PUCHAR)RsaKeyPair, KeyPairLen, &KeyPairLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PrivateKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &PrivateKeyLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    BCRYPT_RSAKEY_BLOB * PrivateKey = (BCRYPT_RSAKEY_BLOB *)ExAllocatePoolWithTag(NonPagedPool, PrivateKeyLen, TAG); 
    ASSERT(PrivateKey);//前四个字节是：RSA2

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, (PUCHAR)PrivateKey, PrivateKeyLen, &PrivateKeyLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ULONG PublicKeyLen = 0;
    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &PublicKeyLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    BCRYPT_RSAKEY_BLOB * PublicKey = (BCRYPT_RSAKEY_BLOB *)ExAllocatePoolWithTag(NonPagedPool, PublicKeyLen, TAG); 
    ASSERT(PublicKey);//前四个字节是：RSA1

    NtStatus = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, (PUCHAR)PublicKey, PublicKeyLen, &PublicKeyLen, 0);
    ASSERT(STATUS_SUCCESS == NtStatus);

    //////////////////////////////////////////////////////////////////////////////////////////////

    DWORD BlockLength = 0;
    ULONG Result;
    NtStatus = BCryptGetProperty(
        hKey, BCRYPT_BLOCK_LENGTH, (PUCHAR)&BlockLength, sizeof(BlockLength), &Result, 0);

    //////////////////////////////////////////////////////////////////////////////////////////////

    const char * Data = "test";
    ULONG DataSize = (ULONG)strlen(Data);

    PUCHAR CipherText = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BlockLength, TAG); 
    ASSERT(CipherText);
    ULONG CipherTextSize = BlockLength;

    PUCHAR PlainText = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BlockLength, TAG);
    ASSERT(PlainText);
    ULONG PlainTextSize = BlockLength;

    RsaPublicKeyEncrypt((PUCHAR)PublicKey, PublicKeyLen, (PUCHAR)Data, DataSize, CipherText, CipherTextSize);
    RsaPrivateKeyDecrypt((PUCHAR)PrivateKey, PrivateKeyLen, CipherText, CipherTextSize, PlainText, PlainTextSize);

    ExFreePoolWithTag(CipherText, TAG);
    ExFreePoolWithTag(PlainText, TAG);

    //////////////////////////////////////////////////////////////////////////////////////////////

    ExFreePoolWithTag(PublicKey, TAG);
    ExFreePoolWithTag(PrivateKey, TAG);
    ExFreePoolWithTag(RsaKeyPair, TAG);

    NtStatus = BCryptDestroyKey(hKey);
    NtStatus = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
}
