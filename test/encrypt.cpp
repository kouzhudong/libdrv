#include "pch.h"
#include "encrypt.h"


void TestRsaEncrypt()
{
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    BCRYPT_RSAKEY_BLOB * RsaKeyPair = nullptr;
    BCRYPT_RSAKEY_BLOB * PrivateKey = nullptr;
    BCRYPT_RSAKEY_BLOB * PublicKey = nullptr;
    PUCHAR CipherText = nullptr;
    PUCHAR PlainText = nullptr;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

    __try {
        NtStatus = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptOpenAlgorithmProvider failed: %#x", NtStatus);
            __leave;
        }

        NtStatus = BCryptGenerateKeyPair(hAlgorithm, &hKey, 3072, 0);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptGenerateKeyPair failed: %#x", NtStatus);
            __leave;
        }

        NtStatus = BCryptFinalizeKeyPair(hKey, 0);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptFinalizeKeyPair failed: %#x", NtStatus);
            __leave;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////

        ULONG KeyPairLen = 0;
        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &KeyPairLen, 0);
        if (!NT_SUCCESS(NtStatus) || !KeyPairLen) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(sizing) failed: %#x", NtStatus);
            __leave;
        }

        RsaKeyPair = (BCRYPT_RSAKEY_BLOB *)ExAllocatePoolWithTag(NonPagedPool, KeyPairLen, TAG);
        if (!RsaKeyPair) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "ExAllocatePoolWithTag(RsaKeyPair) failed");
            __leave;
        }

        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, (PUCHAR)RsaKeyPair, KeyPairLen, &KeyPairLen, 0);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(RSAFULLPRIVATE) failed: %#x", NtStatus);
            __leave;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////

        ULONG PrivateKeyLen = 0;
        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPRIVATE_BLOB, nullptr, 0, &PrivateKeyLen, 0);
        if (!NT_SUCCESS(NtStatus) || !PrivateKeyLen) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(PrivateKey sizing) failed: %#x", NtStatus);
            __leave;
        }

        PrivateKey = (BCRYPT_RSAKEY_BLOB *)ExAllocatePoolWithTag(NonPagedPool, PrivateKeyLen, TAG);
        if (!PrivateKey) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "ExAllocatePoolWithTag(PrivateKey) failed");
            __leave;
        }

        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPRIVATE_BLOB, (PUCHAR)PrivateKey, PrivateKeyLen, &PrivateKeyLen, 0);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(RSAPRIVATE) failed: %#x", NtStatus);
            __leave;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////

        ULONG PublicKeyLen = 0;
        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &PublicKeyLen, 0);
        if (!NT_SUCCESS(NtStatus) || !PublicKeyLen) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(PublicKey sizing) failed: %#x", NtStatus);
            __leave;
        }

        PublicKey = (BCRYPT_RSAKEY_BLOB *)ExAllocatePoolWithTag(NonPagedPool, PublicKeyLen, TAG);
        if (!PublicKey) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "ExAllocatePoolWithTag(PublicKey) failed");
            __leave;
        }

        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, (PUCHAR)PublicKey, PublicKeyLen, &PublicKeyLen, 0);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(RSAPUBLIC) failed: %#x", NtStatus);
            __leave;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////

        DWORD BlockLength = 0;
        ULONG Result = 0;
        NtStatus = BCryptGetProperty(hKey, BCRYPT_BLOCK_LENGTH, (PUCHAR)&BlockLength, sizeof(BlockLength), &Result, 0);
        if (!NT_SUCCESS(NtStatus) || !BlockLength) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptGetProperty(BLOCK_LENGTH) failed: %#x", NtStatus);
            __leave;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////

        const char * Data = "test";
        ULONG DataSize = (ULONG)strlen(Data);
        ULONG CipherTextSize = BlockLength;
        ULONG PlainTextSize = BlockLength;

        CipherText = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BlockLength, TAG);
        if (!CipherText) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "ExAllocatePoolWithTag(CipherText) failed");
            __leave;
        }

        PlainText = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BlockLength, TAG);
        if (!PlainText) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "ExAllocatePoolWithTag(PlainText) failed");
            __leave;
        }

        ULONG ActualCipherSize = 0;
        NtStatus = RsaPublicKeyEncrypt((PUCHAR)PublicKey, PublicKeyLen, (PUCHAR)Data, DataSize, CipherText, CipherTextSize, &ActualCipherSize);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "RsaPublicKeyEncrypt failed: %#x", NtStatus);
            __leave;
        }

        ULONG ActualPlainSize = 0;
        NtStatus = RsaPrivateKeyDecrypt((PUCHAR)PrivateKey, PrivateKeyLen, CipherText, ActualCipherSize, PlainText, PlainTextSize, &ActualPlainSize);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "RsaPrivateKeyDecrypt failed: %#x", NtStatus);
            __leave;
        }
    } __finally {
        if (PlainText)   { ExFreePoolWithTag(PlainText, TAG); }
        if (CipherText)  { ExFreePoolWithTag(CipherText, TAG); }
        if (PublicKey)   { ExFreePoolWithTag(PublicKey, TAG); }
        if (PrivateKey)  { ExFreePoolWithTag(PrivateKey, TAG); }
        if (RsaKeyPair)  { ExFreePoolWithTag(RsaKeyPair, TAG); }
        if (hKey)        { BCryptDestroyKey(hKey); }
        if (hAlgorithm)  { BCryptCloseAlgorithmProvider(hAlgorithm, 0); }
    }
}
