#pragma once


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


BOOL WINAPI CngHashData(_In_z_ LPCWSTR pszAlgId,
                        _In_reads_bytes_(DataSize) PUCHAR Data,
                        _In_ ULONG DataSize,
                        _Out_writes_bytes_all_(*HashSize) PUCHAR * Hash,
                        _In_ ULONG * HashSize);

BOOL HashFile(_In_ PFLT_FILTER Filter,
              __in_opt PFLT_INSTANCE Instance,
              _In_ PUNICODE_STRING FileName,
              _In_ LPWSTR algorithm,
              _Inout_ PUNICODE_STRING lpFileHash);


EXTERN_C_END
