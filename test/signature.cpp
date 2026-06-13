#include "pch.h"
#include "signature.h"


void TestEcdsaSignature()
{
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    PBCRYPT_ECCKEY_BLOB PrivateKey = nullptr;
    PBCRYPT_ECCKEY_BLOB PublicKey = nullptr;
    PUCHAR Sign = nullptr;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

    __try {
        NtStatus = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_ECDSA_P521_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptOpenAlgorithmProvider failed: %#x", NtStatus);
            __leave;
        }

        NtStatus = BCryptGenerateKeyPair(hAlgorithm, &hKey, 521, 0);
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

        ULONG PrivateKeyLen = 0;
        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &PrivateKeyLen, 0);
        if (!NT_SUCCESS(NtStatus) || !PrivateKeyLen) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(PrivateKey sizing) failed: %#x", NtStatus);
            __leave;
        }

        PrivateKey = (PBCRYPT_ECCKEY_BLOB)ExAllocatePoolWithTag(NonPagedPool, PrivateKeyLen, TAG);
        if (!PrivateKey) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "ExAllocatePoolWithTag(PrivateKey) failed");
            __leave;
        }

        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_ECCPRIVATE_BLOB, (PUCHAR)PrivateKey, PrivateKeyLen, &PrivateKeyLen, 0);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(ECCPRIVATE) failed: %#x", NtStatus);
            __leave;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////

        ULONG PublicKeyLen = 0;
        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &PublicKeyLen, 0);
        if (!NT_SUCCESS(NtStatus) || !PublicKeyLen) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(PublicKey sizing) failed: %#x", NtStatus);
            __leave;
        }

        PublicKey = (PBCRYPT_ECCKEY_BLOB)ExAllocatePoolWithTag(NonPagedPool, PublicKeyLen, TAG);
        if (!PublicKey) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "ExAllocatePoolWithTag(PublicKey) failed");
            __leave;
        }

        NtStatus = BCryptExportKey(hKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, (PUCHAR)PublicKey, PublicKeyLen, &PublicKeyLen, 0);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "BCryptExportKey(ECCPUBLIC) failed: %#x", NtStatus);
            __leave;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////

        const char * Data = "test";
        ULONG DataSize = (ULONG)strlen(Data);
        ULONG SignSize = 0;

        NtStatus = SignHashByEcdsa((PUCHAR)PrivateKey, PrivateKeyLen, (PUCHAR)Data, DataSize, &Sign, &SignSize);
        if (!NT_SUCCESS(NtStatus)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "SignHashByEcdsa failed: %#x", NtStatus);
            __leave;
        }

        if (!VerifySignatureByEcdsa((PUCHAR)PublicKey, PublicKeyLen, (PUCHAR)Data, DataSize, Sign, SignSize)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "VerifySignatureByEcdsa: signature verification failed");
        }
    } __finally {
        if (Sign)       { ExFreePoolWithTag(Sign, TAG); }
        if (PublicKey)  { ExFreePoolWithTag(PublicKey, TAG); }
        if (PrivateKey) { ExFreePoolWithTag(PrivateKey, TAG); }
        if (hKey)       { BCryptDestroyKey(hKey); }
        if (hAlgorithm) { BCryptCloseAlgorithmProvider(hAlgorithm, 0); }
    }
}
