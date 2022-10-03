#include "pch.h"
#include "hash.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL HashFile(_In_ PFLT_FILTER Filter,
              __in_opt PFLT_INSTANCE Instance,
              _In_ PUNICODE_STRING FileName,
              _In_ LPWSTR algorithm,
              _Inout_ PUNICODE_STRING lpFileHash
)
/*

FileName��֧�֣�
"\Device\Mup\vmware-host\Shared Folders\...

algorithm��ȡֵ�У�BCRYPT_MD5_ALGORITHM��BCRYPT_SHA1_ALGORITHM��BCRYPT_SHA256_ALGORITHM�ȼ�ʮ�֡�

lpFileHash��ֵ�ɵ������ͷš�
*/
{
    IO_STATUS_BLOCK  IoStatusBlock = {0};
    OBJECT_ATTRIBUTES ObjectAttributes = {0};
    NTSTATUS Status = STATUS_SUCCESS;
    BOOL bResult = FALSE;
    PVOID buffer = NULL;
    HANDLE hFile = NULL;
    HANDLE hAlg = NULL;
    HANDLE hHash = NULL;
    UCHAR hashObj[256] = {0};
    UCHAR Digest[64] = {0};
    DWORD cbHash = 0;
    DWORD nouse = 0;
    ULONG nread = PAGE_SIZE * 4;
    PFILE_OBJECT  FileObject = NULL;

    InitializeObjectAttributes(&ObjectAttributes, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

    do {
        Status = FltCreateFile(Filter,
                               Instance,
                               &hFile,
                               FILE_GENERIC_READ | SYNCHRONIZE,
                               &ObjectAttributes,
                               &IoStatusBlock,
                               0,
                               FILE_ATTRIBUTE_NORMAL,
                               FILE_SHARE_VALID_FLAGS,
                               FILE_OPEN,
                               FILE_NON_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT,
                               NULL,
                               0,
                               IO_IGNORE_SHARE_ACCESS_CHECK);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, FileName:%wZ", Status, FileName);
            break;
        }

        //���������Ķ�Ӧ���Ż���һ���������������Ĵ�ṹ, Ȼ���Ժ��б����, �����Ƿ�ɢ���������з����ͷ�
        buffer = ExAllocatePoolWithTag(PagedPool, nread, TAG);
        if (buffer == NULL) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, FileName:%wZ", Status, FileName);
            break;
        }

        Status = BCryptOpenAlgorithmProvider(&hAlg, algorithm, NULL, 0);
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

        Status = BCryptCreateHash(hAlg, &hHash, hashObj, sizeof(hashObj), NULL, 0, 0);
        ASSERT(NT_SUCCESS(Status));

        Status = ObReferenceObjectByHandle(hFile, 
                                           FILE_LIST_DIRECTORY | SYNCHRONIZE, 
                                           *IoFileObjectType, 
                                           KernelMode,
                                           (PVOID *)&FileObject,
                                           NULL);
        ASSERT(NT_SUCCESS(Status));

        for (;;) {
            ULONG  BytesRead = 0;

            if (NULL == Instance) {
                Status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, buffer, nread, NULL, NULL);
            } else {//��һ��������׼ΪNULL��
                Status = FltReadFile(Instance, FileObject, NULL, nread, buffer, 0, &BytesRead, NULL, NULL);
            }
            if (!NT_SUCCESS(Status)) {
                if (Status == STATUS_END_OF_FILE) {
                    Status = STATUS_SUCCESS;
                } else {
                    PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x, FileName:%wZ", Status, FileName);                    
                }

                break;
            }

            if (NULL == Instance) {
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
        if (NULL == lpFileHash->Buffer) {
            Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
            break;
        }
        RtlZeroMemory(lpFileHash->Buffer, lpFileHash->MaximumLength);

        {
            DWORD i = 0;
            WCHAR * ptr = lpFileHash->Buffer;
            for (; i < cbHash; i++) {
                //linus�ľ���д��
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
