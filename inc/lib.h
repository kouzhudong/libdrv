/*
�������ṩ������Ĺ���ʹ�õġ�

����Ķ��ǵ����ĺ������������ṹ�������Ϣ��
*/


#pragma once


#if (NTDDI_VERSION >= NTDDI_VISTA)
#define NDIS60 1
#define NDIS_SUPPORT_NDIS6 1
#endif 

#define POOL_NX_OPTIN 1
#define _CRT_NON_CONFORMING_SWPRINTFS
#define INITGUID
#define NTSTRSAFE_LIB

#pragma warning(disable:4200) // ʹ���˷Ǳ�׼��չ : �ṹ/�����е����С����
#pragma warning(disable:4201) // unnamed struct/union
#pragma warning(disable:4214) // ʹ���˷Ǳ�׼��չ: ���������λ������
#pragma warning(disable:4127) // �������ʽ�ǳ���
#pragma warning(disable:4057) // ����΢��ͬ�Ļ����ͼ��Ѱַ�ϲ�ͬ
#pragma warning(disable:4152) // �Ǳ�׼��չ�����ʽ�еĺ���/����ָ��ת��
#pragma warning(disable:28172) //The function 'XXX' has PAGED_CODE or PAGED_CODE_LOCKED but is not declared to be in a paged segment. ԭ��1.������IRQL������2.�����ڵĺ����Ĳ����þֲ���������Ҫ����������ǷǷ�ҳ�ڴ档

#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <windef.h> //Ӧ�÷���ntddk.h�ĺ���.
#include <in6addr.h>
#include <ip2string.h>
#include <guiddef.h>
#include <ndis.h>
#include <initguid.h> //��̬����UUID�õģ�����error LNK2001��
#include <Ntstrsafe.h>
#include <ipmib.h>
#include <netpnp.h>
#include <ntintsafe.h>
#include <fltkernel.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <Bcrypt.h>

/*
WDK7600.16385.1���ں�ͷ�ļ�û��u_short�Ķ���,�û����ͷ�ļ���u_short�Ķ���.
SOCKADDR�ṹ���õ�u_short.
SOCKADDR��ws2def.h�ж���.
ws2def.h������ֱ�Ӱ���.
netioapi.h����ws2def.h���ļ�.
������WDK7600.16385.1��,���������Ӧ�ò��ͷ�ļ�,Ӧ���ڰ���netioapi.h֮ǰ,����u_short�Ķ���.
����,ÿ������(������Ӱ���)ws2def.h��c/cpp�ļ�������һ��ѵĴ���.
*/
typedef unsigned short  u_short;
#include <netioapi.h>
//#include <ws2def.h>
#include <ws2ipdef.h>
#include <mstcpip.h>
#include <wmilib.h>
#include <wmistr.h>
#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>
#include <tdistat.h>
//#include <fwpmk.h>
#include <wsk.h>
#include <ntimage.h>
#include <fwpsk.h>  //NDIS61
#include <dontuse.h>
#include <suppress.h>
#include <aux_klib.h>
#include <assert.h>
#include <Ntdddisk.h>
#include <intrin.h> //VS2012���롣
#include <immintrin.h>//VS2012���롣
//#include <mmintrin.h> //WDK ���롣
//#include <emmintrin.h>//WDK ���롣
//#include <xmmintrin.h>//WDK ���롣


//////////////////////////////////////////////////////////////////////////////////////////////////
//�Լ������һЩ�ص�����ԭ�͡�


typedef NTSTATUS(WINAPI * HandleProcess)(_In_ HANDLE UniqueProcessId, _In_opt_ PVOID Context);

typedef NTSTATUS(WINAPI * HandleThread) (_In_ PCLIENT_ID Cid, _In_opt_ PVOID Context);

typedef NTSTATUS(WINAPI * HandleKernelModule)(_In_ ULONG numberOfModules,
                                              _In_ PAUX_MODULE_EXTENDED_INFO ModuleInfo,
                                              _In_opt_ PVOID Context);

typedef NTSTATUS(WINAPI * HandleUserModule)(_In_ PVOID DllBase,
                                            _In_ PUNICODE_STRING FullDllName,
                                            _In_opt_ PVOID Context);

typedef NTSTATUS(NTAPI * HandleSection)(_In_ PVOID ViewBase, _In_ SIZE_T ViewSize, _In_opt_ PVOID Context);

typedef void (*PAPCFUNC)(ULONG_PTR Parameter);

//\WRK-v1.2\public\sdk\inc\ntpsapi.h
typedef VOID(*PPS_APC_ROUTINE) (__in_opt PVOID ApcArgument1,
                                __in_opt PVOID ApcArgument2,
                                __in_opt PVOID ApcArgument3);

typedef NTSTATUS(WINAPI * VirtualMemoryCallBack)(_In_ HANDLE Pid,
                                                 _In_ PMEMORY_BASIC_INFORMATION MemoryBasicInfo,
                                                 _In_opt_ PVOID Context);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


//////////////////////////////////////////////////////////////////////////////////////////////////
//�ļ���صĵ����ĺ�����


BOOLEAN CopyFile(IN PWCH DestinationFile, IN PWCH SourceFile, IN BOOLEAN bFailIfExists);
BOOLEAN CopyFileEx(IN UNICODE_STRING * FileName, IN UNICODE_STRING * newFileName);
BOOLEAN ZwCopyFile(IN UNICODE_STRING * FileName, IN UNICODE_STRING * newFileName);
NTSTATUS IrpCopyFile(UNICODE_STRING * name, UNICODE_STRING * newFileName);

BOOLEAN FltCopyFile(_In_ PFLT_FILTER Filter,
                    __inout PFLT_CALLBACK_DATA Data,
                    IN UNICODE_STRING * FileName,
                    IN UNICODE_STRING * newFileName);

NTSTATUS ZwEnumerateFile(IN UNICODE_STRING * directory);
NTSTATUS ZwEnumerateFileEx(IN UNICODE_STRING * directory);

VOID NTAPI WriteDiskSector(INT DiskIndex, LONGLONG StartingOffset, PVOID Buffer, ULONG Length);
VOID NTAPI ReadMBR(IN PDEVICE_OBJECT DeviceObject, IN ULONG SectorSize, OUT PVOID * Buffer);

NTSTATUS FltGetFileNameInformationEx(__inout PFLT_CALLBACK_DATA Cbd,
                                     __in PCFLT_RELATED_OBJECTS FltObjects,
                                     OUT PUNICODE_STRING usFullPath);

#if (NTDDI_VERSION < NTDDI_VISTA)
NTSTATUS FltQueryDirectoryFile( //FltQueryDirectoryFile_XP ΪXP��������FltQueryDirectoryFile
                               _In_ PFLT_INSTANCE Instance,
                               _In_ PFILE_OBJECT FileObject,
                               _Out_writes_bytes_(Length) PVOID FileInformationBuffer,
                               _In_ ULONG Length,
                               _In_ FILE_INFORMATION_CLASS FileInformationClass,
                               _In_ BOOLEAN ReturnSingleEntry,
                               _In_opt_ PUNICODE_STRING FileName,
                               _In_ BOOLEAN RestartScan,
                               _Out_opt_ PULONG LengthReturned
);
#endif

#if (NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS IoReplaceFileObjectName(_In_ PFILE_OBJECT FileObject,
                                 _In_reads_bytes_(FileNameLength) PWSTR NewFileName,
                                 _In_ USHORT FileNameLength);
#endif

VOID PrintVolume(__in PCFLT_RELATED_OBJECTS FltObjects);

NTSTATUS ZwGetDosFileName(_Inout_ PFLT_CALLBACK_DATA Data,
                          _In_ PCFLT_RELATED_OBJECTS FltObjects,
                          OUT PUNICODE_STRING DosFileName);

void GetSystemRootPathName(PUNICODE_STRING PathName, PUNICODE_STRING NtPathName, PUNICODE_STRING DosPathName);

NTSTATUS GetSystemRootName(_In_ PUNICODE_STRING SymbolicLinkName,
                           _Inout_ PUNICODE_STRING NtPathName,
                           _Inout_ PUNICODE_STRING DosPathName
);

NTSTATUS ZwCreateHardLink(__in PUNICODE_STRING HardLinkFileName, __in PUNICODE_STRING  ExistingFileName);


//////////////////////////////////////////////////////////////////////////////////////////////////
//�㷨��صġ�


BOOL HashFile(_In_ PFLT_FILTER Filter,
              __in_opt PFLT_INSTANCE Instance,
              _In_ PUNICODE_STRING FileName,
              _In_ LPWSTR algorithm,
              _Inout_ PUNICODE_STRING lpFileHash);


//////////////////////////////////////////////////////////////////////////////////////////////////
//ģ����ص�


VOID EnumUserModule(_In_ HANDLE Pid, _In_opt_ HandleUserModule CallBack, _In_opt_ PVOID Context);

#if (NTDDI_VERSION >= NTDDI_VISTA)
PVOID GetNtBase();
PVOID GetImageBase(__in PCSTR name);
NTSTATUS EnumKernelModule(_In_ HandleKernelModule CallBack, _In_opt_ PVOID Context);
#endif

BOOLEAN MapViewOfSection(_In_ PUNICODE_STRING ImageFileName,
                         _In_opt_ HandleSection CallBack,
                         _In_opt_ PVOID Context);

NTSTATUS GetMemoryMappedFilenameInformation(_In_ HANDLE KernelProcessHandle, 
                                            _In_opt_ PVOID DllBase,
                                            _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                                            _In_ SIZE_T MemoryInformationLength);

NTSTATUS ZwGetSystemModuleInformation();

VOID NTAPI RtlGetLoadImageFullName(_Inout_ PUNICODE_STRING LoadImageFullName,
                                   __in_opt PUNICODE_STRING  FullImageName,
                                   __in HANDLE  ProcessId,
                                   __in PIMAGE_INFO  ImageInfo);


//////////////////////////////////////////////////////////////////////////////////////////////////
//�ڴ���ء�


NTSTATUS WINAPI EnumVirtualMemory(_In_ HANDLE Pid, _In_opt_ VirtualMemoryCallBack CallBack, _In_opt_ PVOID Context);


//////////////////////////////////////////////////////////////////////////////////////////////////
//����


_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_same_
_Success_(return == STATUS_SUCCESS)
NTSTATUS Sleep(_In_ UINT32 numMS);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN RtlIsNameInExpression(_In_ PUNICODE_STRING Expression, _In_ PUNICODE_STRING Name);

NTSTATUS AllocateUnicodeString(_In_ PUNICODE_STRING String);
VOID FreeUnicodeString(_In_ PUNICODE_STRING String);

LONG ExceptionFilter(_In_ PEXCEPTION_POINTERS ExceptionPointer);

void ConvertFormatTimeToSystemTime(IN wchar_t * rule_text, OUT PLARGE_INTEGER st);
void ConvertSystemTimeToFormatTime(IN PLARGE_INTEGER st, OUT PUNICODE_STRING pus);
ULONG GetCurrnetTime();

void StringToInteger(wchar_t * rule_text, PULONG y);
void StringToLUID(wchar_t * rule_text, PLARGE_INTEGER pli);


//////////////////////////////////////////////////////////////////////////////////////////////////
//������صġ�


NTSTATUS EnumUnicastIpAddressTable();

NTSTATUS EnumIpPathTable();

NTSTATUS EnumAnycastIpAddressTable();

NTSTATUS EnumIfTable2();

NTSTATUS EnumIfTable2Ex();

NTSTATUS EnumIpInterfaceTable();

NTSTATUS EnumIpForwardTable2();

NTSTATUS EnumIfStackTable();

NTSTATUS EnumIpNetTable2();

NTSTATUS EnumMulticastIpAddressTable();

void NetioEnumTest();


//////////////////////////////////////////////////////////////////////////////////////////////////
//object��


NTSTATUS GetObjectNtName(_In_ PVOID Object, _Inout_ PUNICODE_STRING NtName);
NTSTATUS GetObjectName(_In_ PVOID Object, _Inout_ PUNICODE_STRING ObjectName);
NTSTATUS GetFileObjectDosName(_In_ PFILE_OBJECT FileObject, _Inout_ PUNICODE_STRING DosName);
void GetKnownDllPath();
void GetKnownDllPathEx();
NTSTATUS ZwEnumerateObject(_In_ PUNICODE_STRING Directory);
NTSTATUS ZwEnumerateDriverObject();

#if (NTDDI_VERSION >= NTDDI_VISTA)
void EnumerateTransactionObject();
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////
//PE�ļ���صġ�


PVOID MiFindExportedRoutineByName(_In_ PVOID DllBase, _In_ PANSI_STRING AnsiImageRoutineName);
PVOID MiFindExportedRoutineByNameEx(_In_ PVOID DllBase, _In_ PANSI_STRING AnsiImageRoutineName);
PVOID GetUserFunctionAddressByPeb(_In_ HANDLE ProcessId, _In_ PWSTR DllFullName, _In_ PSTR FunctionName);
PVOID GetUserFunctionAddress(_In_ HANDLE ProcessId, _In_ PWSTR DllFullName, _In_ PSTR FunctionName);
BOOL IsPe64(_In_ PVOID ImageBase);
VOID ModifyPeEntry(_In_ PVOID ImageBase);
NTSTATUS ExtraFile(_In_ PCSTR FileName, _In_ ULONG_PTR Type, _In_ ULONG_PTR Id, _In_ PUNICODE_STRING NewFileName);
BOOL IsFilePe64(_In_ PUNICODE_STRING ImageFileName);
BOOL IsProcessPe64(_In_ HANDLE UniqueProcess);


//////////////////////////////////////////////////////////////////////////////////////////////////
//������صġ�


BOOL GetCommandLine(_In_ HANDLE PId, _Inout_ PUNICODE_STRING CommandLine);

BOOL GetCurrentDirectory(_In_ HANDLE Pid, _Inout_ PUNICODE_STRING CurrentDirectory);

NTSTATUS GetUserOfProcess(_In_ HANDLE Pid, _Out_ PUNICODE_STRING User);

BOOL GetFullDosProcessImageFileName(_In_ PFLT_FILTER Filter,
                                    _In_opt_ PFLT_INSTANCE Instance,
                                    _In_ HANDLE Pid,
                                    _Inout_ PUNICODE_STRING FileName);

BOOL GetFullNtProcessImageFileName(_In_ HANDLE Pid, _Inout_ PUNICODE_STRING * ProcessFileName);

BOOL GetProcessImageName(_In_ HANDLE pid, _Inout_ PUNICODE_STRING ImagePathName);

NTSTATUS GetLogonId(_Inout_ PLUID LogonId);

DWORD GetProcessIntegrityLevel(_In_ HANDLE UniqueProcess);

DWORD GetSessionId(_In_ PEPROCESS Process);

NTSTATUS GetPidFromProcessName(_In_ PWSTR ProcessName, _Inout_ PHANDLE UniqueProcessId);

NTSTATUS EnumProcess(_In_ HandleProcess CallBack, _In_opt_ PVOID Context);

BOOL GetProcessImageFileName(_In_ HANDLE Pid, _Inout_ PUNICODE_STRING ProcessName);

HANDLE GetParentsPID(_In_ HANDLE UniqueProcessId);

NTSTATUS GetAllChildProcess(_In_ HANDLE UniqueProcessId);

NTSTATUS GetJobNameOfProcess(_In_ HANDLE Pid);

NTSTATUS ZwAllocateHeap();

NTSTATUS IsSecureProcess(_In_ HANDLE ProcessHandle, _Out_ BOOLEAN * SecureProcess);
NTSTATUS IsProtectedProcess(_In_ HANDLE ProcessHandle, _Out_ BOOLEAN * ProtectedProcess);
BOOLEAN IsWow64Process(_In_ HANDLE ProcessHandle);

NTSTATUS AdjustPrivilege(ULONG Privilege, BOOLEAN Enable);


//////////////////////////////////////////////////////////////////////////////////////////////////
//ע�����صġ�


NTSTATUS ZwEnumerateKeyEx(IN UNICODE_STRING * Name);
NTSTATUS ZwCopyKey(IN UNICODE_STRING * Name, IN UNICODE_STRING * Name2);
NTSTATUS ZwCreateRootKey(_In_ POBJECT_ATTRIBUTES RegisterKey, _In_ POBJECT_ATTRIBUTES HiveFile);
NTSTATUS GetKeyFullName(_In_ PREG_CREATE_KEY_INFORMATION Info, _Inout_ PUNICODE_STRING FullKeyName);


//////////////////////////////////////////////////////////////////////////////////////////////////
//SSDT


//ԭ��ժ�ԣ�\Windows Kits\10\Include\10.0.19041.0\km\ntifs.h
//����\Windows Kits\10\Include\10.0.19041.0\km\ntifs.h����(NTDDI_VERSION >= NTDDI_WIN2K)��
//�������ڵ�ϵͳ��XP����û�е������������
//�����д˶��塣
typedef
NTSTATUS
(NTAPI * ZwQueryVirtualMemory_PFN) (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );


typedef
NTSTATUS
(WINAPI * ZwTerminateThread_pfn)(
    __in_opt HANDLE ThreadHandle,
    __in NTSTATUS ExitStatus
    );


//Win2K3\NT\public\sdk\inc\ntrtl.h
typedef NTSTATUS(*PUSER_THREAD_START_ROUTINE)(PVOID ThreadParameter);


//�˺����Ѿ����������Ǳ��뻷���������ƺ��ı���û��������塣
//ֻ����MmGetSystemRoutineAddress��ȡ���ɡ�
typedef
NTSTATUS(NTAPI *
         RtlCreateUserThreadFn)(
             IN HANDLE Process,
             IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
             IN BOOLEAN CreateSuspended,
             IN ULONG ZeroBits OPTIONAL,
             IN SIZE_T MaximumStackSize OPTIONAL,
             IN SIZE_T CommittedStackSize OPTIONAL,
             IN PUSER_THREAD_START_ROUTINE StartAddress,
             IN PVOID Parameter OPTIONAL,
             OUT PHANDLE Thread OPTIONAL,
             OUT PCLIENT_ID ClientId OPTIONAL
             );


void SetZwQueryVirtualMemoryAddress(_In_ ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryAddress);
void SetZwTerminateThreadAddress(_In_ ZwTerminateThread_pfn ZwTerminateThreadAddress);
void SetRtlCreateUserThreadAddress(_In_ RtlCreateUserThreadFn RtlCreateUserThreadAddress);

SIZE_T GetZwRoutineAddress(PCSTR RoutineName);


//////////////////////////////////////////////////////////////////////////////////////////////////
//�߳���صġ�


NTSTATUS GetThreadStartAddress(_In_ HANDLE  ThreadId, _Inout_ PVOID * StartAddress);
NTSTATUS GetThreadNumbers(_In_ HANDLE  ProcessId, _Inout_ PINT thread_number);
NTSTATUS KillSystemThread(_In_ PETHREAD Thread);
NTSTATUS KillUserThread(_In_ PETHREAD Thread);
NTSTATUS EnumThread(_In_ HANDLE UniqueProcessId, _In_ HandleThread CallBack, _In_opt_ PVOID Context);

//Win2K3\NT\public\sdk\inc\ntrtl.h
typedef NTSTATUS(*PUSER_THREAD_START_ROUTINE)(PVOID ThreadParameter);

NTSTATUS CreateUserThread(_In_ HANDLE Pid,
                          _In_ PUSER_THREAD_START_ROUTINE Function,
                          _In_ PVOID Parameter,
                          _Inout_ PHANDLE ThreadHandleReturn,
                          _Inout_ PCLIENT_ID ClientId
);

DWORD WINAPI QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);

NTSTATUS NTAPI NtQueueApcThread(__in HANDLE ThreadHandle,
                                __in PPS_APC_ROUTINE ApcRoutine,
                                __in_opt PVOID ApcArgument1,
                                __in_opt PVOID ApcArgument2,
                                __in_opt PVOID ApcArgument3);

NTSTATUS NTAPI NtQueueApcThreadEx(__in HANDLE ThreadHandle,
                                  __in PPS_APC_ROUTINE ApcRoutine,
                                  __in_opt PVOID ApcArgument1,
                                  __in_opt PVOID ApcArgument2,
                                  __in_opt PVOID ApcArgument3);

VOID GetApcStateOffset(PSIZE_T ApcStateOffset);


//////////////////////////////////////////////////////////////////////////////////////////////////
//CPU��صġ�


VOID DisSmep();
struct _KPRCB * KeGetPrcb(PKPCR pkpcr);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
