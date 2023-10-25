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
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS Status = STATUS_SUCCESS;

    __try {
        Status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = BCryptImportKeyPair(hAlgorithm,
                                     nullptr,
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
                               nullptr,
                               nullptr,
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
    BCRYPT_ALG_HANDLE hAlgorithm = nullptr;
    NTSTATUS Status = STATUS_SUCCESS;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    __try {
        Status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        Status = BCryptImportKeyPair(hAlgorithm,
                                     nullptr,
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
                               nullptr,
                               nullptr,
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


void WINAPI AesEncryptDecryptTest()
/*
Encrypting Data with CNG
2018/05/31

以后有空了，把这个函数拆分为加密和解密的两个函数。

https://docs.microsoft.com/zh-cn/windows/win32/seccng/encrypting-data-with-cng
*/
{
    BCRYPT_ALG_HANDLE       hAesAlg = nullptr;
    BCRYPT_KEY_HANDLE       hKey = nullptr;
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;
    DWORD cbCipherText = 0, cbPlainText = 0, cbData = 0, cbKeyObject = 0, cbBlockLen = 0, cbBlob = 0;
    PBYTE pbCipherText = nullptr, pbPlainText = nullptr, pbKeyObject = nullptr, pbIV = nullptr, pbBlob = nullptr;

    const BYTE rgbPlaintext[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static const BYTE rgbIV[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    static const BYTE rgbAES128Key[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    __try {

    // Open an algorithm handle.
        if (!NT_SUCCESS(Status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Calculate the size of the buffer to hold the KeyObject.
        if (!NT_SUCCESS(Status = BCryptGetProperty(hAesAlg,
                                                   BCRYPT_OBJECT_LENGTH,
                                                   (PBYTE)&cbKeyObject,
                                                   sizeof(DWORD),
                                                   &cbData,
                                                   0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Allocate the key object on the heap.
        pbKeyObject = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, cbKeyObject, TAG);
        if (nullptr == pbKeyObject) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Calculate the block length for the IV.
        if (!NT_SUCCESS(Status = BCryptGetProperty(hAesAlg,
                                                   BCRYPT_BLOCK_LENGTH,
                                                   (PBYTE)&cbBlockLen,
                                                   sizeof(DWORD),
                                                   &cbData,
                                                   0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Determine whether the cbBlockLen is not longer than the IV length.
        if (cbBlockLen > sizeof(rgbIV)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Allocate a buffer for the IV. The buffer is consumed during the encrypt/decrypt process.
        pbIV = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, cbBlockLen, TAG);
        if (nullptr == pbIV) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        memcpy(pbIV, rgbIV, cbBlockLen);

        if (!NT_SUCCESS(Status = BCryptSetProperty(hAesAlg,
                                                   BCRYPT_CHAINING_MODE,
                                                   (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                                                   sizeof(BCRYPT_CHAIN_MODE_CBC),
                                                   0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Generate the key from supplied input key bytes.
        if (!NT_SUCCESS(Status = BCryptGenerateSymmetricKey(hAesAlg,
                                                            &hKey,
                                                            pbKeyObject,
                                                            cbKeyObject,
                                                            (PBYTE)rgbAES128Key,
                                                            sizeof(rgbAES128Key),
                                                            0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Save another copy of the key for later.
        if (!NT_SUCCESS(Status = BCryptExportKey(hKey, nullptr, BCRYPT_OPAQUE_KEY_BLOB, nullptr, 0, &cbBlob, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Allocate the buffer to hold the BLOB.
        pbBlob = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, cbBlob, TAG);
        if (nullptr == pbBlob) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        if (!NT_SUCCESS(Status = BCryptExportKey(hKey, nullptr, BCRYPT_OPAQUE_KEY_BLOB, pbBlob, cbBlob, &cbBlob, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        cbPlainText = sizeof(rgbPlaintext);
        pbPlainText = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, cbPlainText, TAG);
        if (nullptr == pbPlainText) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        memcpy(pbPlainText, rgbPlaintext, sizeof(rgbPlaintext));

        // Get the output buffer size.
        if (!NT_SUCCESS(Status = BCryptEncrypt(hKey,
                                               pbPlainText,
                                               cbPlainText,
                                               nullptr,
                                               pbIV,
                                               cbBlockLen,
                                               nullptr,
                                               0,
                                               &cbCipherText,
                                               BCRYPT_BLOCK_PADDING))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        pbCipherText = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, cbCipherText, TAG);
        if (nullptr == pbCipherText) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Use the key to encrypt the plaintext buffer.
        // For block sized messages, block padding will add an extra block.
        if (!NT_SUCCESS(Status = BCryptEncrypt(hKey,
                                               pbPlainText,
                                               cbPlainText,
                                               nullptr,
                                               pbIV,
                                               cbBlockLen,
                                               pbCipherText,
                                               cbCipherText,
                                               &cbData,
                                               BCRYPT_BLOCK_PADDING))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Destroy the key and reimport from saved BLOB.
        if (!NT_SUCCESS(Status = BCryptDestroyKey(hKey))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        hKey = nullptr;

        if (pbPlainText) {
            ExFreePoolWithTag(pbPlainText, TAG);
        }

        pbPlainText = nullptr;

        memset(pbKeyObject, 0, cbKeyObject);// We can reuse the key object.    
        memcpy(pbIV, rgbIV, cbBlockLen);// Reinitialize the IV because encryption would have modified it.
        if (!NT_SUCCESS(Status = BCryptImportKey(hAesAlg,
                                                 nullptr,
                                                 BCRYPT_OPAQUE_KEY_BLOB,
                                                 &hKey,
                                                 pbKeyObject,
                                                 cbKeyObject,
                                                 pbBlob,
                                                 cbBlob,
                                                 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        // Get the output buffer size.
        if (!NT_SUCCESS(Status = BCryptDecrypt(hKey,
                                               pbCipherText,
                                               cbCipherText,
                                               nullptr,
                                               pbIV,
                                               cbBlockLen,
                                               nullptr,
                                               0,
                                               &cbPlainText,
                                               BCRYPT_BLOCK_PADDING))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        pbPlainText = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, cbPlainText, TAG);
        if (nullptr == pbPlainText) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        if (!NT_SUCCESS(Status = BCryptDecrypt(hKey,
                                               pbCipherText,
                                               cbCipherText,
                                               nullptr,
                                               pbIV,
                                               cbBlockLen,
                                               pbPlainText,
                                               cbPlainText,
                                               &cbPlainText,
                                               BCRYPT_BLOCK_PADDING))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

    #pragma warning(push)
    #pragma warning(disable:6385)//正在从 "pbPlainText" 读取无效数据。
        if (0 != memcmp(pbPlainText, (PBYTE)rgbPlaintext, sizeof(rgbPlaintext))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }
    #pragma warning(pop)           

        //wprintf(L"Success!\n");
    } __finally {
        if (hAesAlg) {
            BCryptCloseAlgorithmProvider(hAesAlg, 0);
        }

        if (hKey) {
            BCryptDestroyKey(hKey);
        }

        if (pbCipherText) {
            ExFreePoolWithTag(pbCipherText, TAG);
        }

        if (pbPlainText) {
            ExFreePoolWithTag(pbPlainText, TAG);
        }

        if (pbKeyObject) {
            ExFreePoolWithTag(pbKeyObject, TAG);
        }

        if (pbIV) {
            ExFreePoolWithTag(pbIV, TAG);
        }
    }
}
