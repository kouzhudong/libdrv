#include "pch.h"
#include "hash.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL WINAPI CngHashData(_In_z_ LPCWSTR pszAlgId,
                        _In_reads_bytes_(DataSize) PUCHAR Data,
                        _In_ ULONG DataSize,
                        _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                        _In_ ULONG * HashSize
)
/*++

Hash需要由调用者调用ExFreePoolWithTag释放。

https://docs.microsoft.com/zh-cn/windows/win32/seccng/creating-a-hash-with-cng
--*/
{
    BCRYPT_ALG_HANDLE       hAlg = nullptr;
    BCRYPT_HASH_HANDLE      hHash = nullptr;
    NTSTATUS                Status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0, cbHashObject = 0;
    PBYTE                   pbHashObject = nullptr;
    BOOL                    ret = FALSE;

    __try {
    //open an algorithm handle
        if (!NT_SUCCESS(Status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, nullptr, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //calculate the size of the buffer to hold the hash object
        if (!NT_SUCCESS(Status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //allocate the hash object on the heap
        pbHashObject = (PBYTE)ExAllocatePoolWithTag(NonPagedPool, cbHashObject, TAG); 
        if (nullptr == pbHashObject) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //calculate the length of the hash
        if (!NT_SUCCESS(Status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)HashSize, sizeof(DWORD), &cbData, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //allocate the hash buffer on the heap
        *Hash = (PBYTE)ExAllocatePoolWithTag(NonPagedPool,  *HashSize, TAG); 
        if (nullptr == *Hash) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //create a hash
        if (!NT_SUCCESS(Status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, nullptr, 0, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }


        //hash some data
        if (!NT_SUCCESS(Status = BCryptHashData(hHash, Data, DataSize, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        //close the hash
        if (!NT_SUCCESS(Status = BCryptFinishHash(hHash, *Hash, *HashSize, 0))) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            __leave;
        }

        ret = TRUE;
    } __finally {
        if (hAlg) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
        }

        if (hHash) {
            BCryptDestroyHash(hHash);
        }

        if (pbHashObject) {
            ExFreePoolWithTag(pbHashObject, TAG);
        }

        //if (*Hash) {
        //    ExFreePoolWithTag(*Hash, TAG); 
        //}
    }

    return ret;
}


BOOL HashFile(_In_ PFLT_FILTER Filter, __in_opt PFLT_INSTANCE Instance, _In_ PUNICODE_STRING FileName, _In_ LPWSTR algorithm, _Inout_ PUNICODE_STRING lpFileHash)
/*

FileName不支持：
"\Device\Mup\vmware-host\Shared Folders\...

algorithm的取值有：BCRYPT_MD5_ALGORITHM，BCRYPT_SHA1_ALGORITHM，BCRYPT_SHA256_ALGORITHM等几十种。

lpFileHash的值由调用者释放。
*/
{
    IO_STATUS_BLOCK  IoStatusBlock{};
    OBJECT_ATTRIBUTES ObjectAttributes{};
    NTSTATUS Status = STATUS_SUCCESS;
    BOOL bResult = FALSE;
    PVOID buffer = nullptr;
    HANDLE hFile = nullptr;
    HANDLE hAlg = nullptr;
    HANDLE hHash = nullptr;
    UCHAR hashObj[256] = {0};
    UCHAR Digest[64] = {0};
    DWORD cbHash = 0;
    DWORD nouse = 0;
    ULONG nread = PAGE_SIZE * 4;
    PFILE_OBJECT  FileObject = nullptr;

    InitializeObjectAttributes(&ObjectAttributes, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

    do {
        Status = FltCreateFile(Filter,
                               Instance,
                               &hFile,
                               FILE_GENERIC_READ | SYNCHRONIZE,
                               &ObjectAttributes,
                               &IoStatusBlock,
                               nullptr,
                               FILE_ATTRIBUTE_NORMAL,
                               FILE_SHARE_VALID_FLAGS,
                               FILE_OPEN,
                               FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT,
                               nullptr,
                               0,
                               IO_IGNORE_SHARE_ACCESS_CHECK);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, FileName:%wZ", Status, FileName);
            break;
        }

        //整个上下文都应该优化成一块自描述的完整的大结构, 然后以后备列表管理, 而不是分散到各处进行分配释放
        buffer = ExAllocatePoolWithTag(PagedPool, nread, TAG);
        if (buffer == nullptr) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, FileName:%wZ", Status, FileName);
            break;
        }

        Status = BCryptOpenAlgorithmProvider(&hAlg, algorithm, nullptr, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, FileName:%wZ", Status, FileName);
            break;
        }

        Status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &nouse, 0);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, FileName:%wZ", Status, FileName);
            break;
        }

        ASSERT(nouse == 4);

        Status = BCryptCreateHash(hAlg, &hHash, hashObj, sizeof(hashObj), nullptr, 0, 0);
        ASSERT(NT_SUCCESS(Status));

        Status = ObReferenceObjectByHandle(hFile, FILE_LIST_DIRECTORY | SYNCHRONIZE, *IoFileObjectType, KernelMode, (PVOID *)&FileObject, nullptr);
        ASSERT(NT_SUCCESS(Status));

        for (;;) {
            ULONG  BytesRead = 0;

            if (nullptr == Instance) {
                Status = ZwReadFile(hFile, nullptr, nullptr, nullptr, &IoStatusBlock, buffer, nread, nullptr, nullptr);
            } else {//第一个参数不准为NULL。
                Status = FltReadFile(Instance, FileObject, nullptr, nread, buffer, 0, &BytesRead, nullptr, nullptr);
            }
            if (!NT_SUCCESS(Status)) {
                if (Status == STATUS_END_OF_FILE) {
                    Status = STATUS_SUCCESS;
                } else {
                    PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, FileName:%wZ", Status, FileName);
                }

                break;
            }

            if (nullptr == Instance) {
                BytesRead = (ULONG)IoStatusBlock.Information;
            }

            if (BytesRead == 0) {
                break;
            }

            Status = BCryptHashData(hHash, (PUCHAR)buffer, BytesRead, 0);
            if (!NT_SUCCESS(Status)) {
                PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, FileName:%wZ", Status, FileName);
                break;
            }
        }

        Status = BCryptFinishHash(hHash, Digest, cbHash, 0);
        if (!NT_SUCCESS(Status)) {
            break;
        }

        lpFileHash->MaximumLength = (USHORT)cbHash * 4 + sizeof(wchar_t);
        lpFileHash->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, lpFileHash->MaximumLength, TAG);
        if (nullptr == lpFileHash->Buffer) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
            break;
        }
        RtlZeroMemory(lpFileHash->Buffer, lpFileHash->MaximumLength);

        {
            DWORD i = 0;
            WCHAR * ptr = lpFileHash->Buffer;
            for (; i < cbHash; i++) {
                //linus的经典写法
                *ptr++ = L"0123456789ABCDEF"[(Digest[i] >> 4) & 0x0f];
                *ptr++ = L"0123456789ABCDEF"[Digest[i] & 0x0f];
            }
        }

        lpFileHash->Length = (USHORT)cbHash * sizeof(wchar_t);
        bResult = TRUE;
    } while (0);

    if (buffer) {
        ExFreePoolWithTag(buffer, TAG);
    }

    if (hHash) {
        BCryptDestroyHash(hHash);
    }

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    if (FileObject) {
        ObDereferenceObject(FileObject);
    }

    if (hFile) {
        FltClose(hFile);
    }

    return bResult;
}
