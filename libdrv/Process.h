#pragma once

#include "pch.h"
#include "ProcessInfo.h"
#include "PEB.h"
#include "SystemInfo.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
RTL_USER_PROCESS_PARAMETERS在如下两个文件中有定义：
wrk\WindowsResearchKernel-WRK\WRK-v1.2\public\sdk\inc\ntrtl.h
\win2k\private\windbg64\debugger\include\sundown.h
这里采用WRK的。
*/

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5 )

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE      0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT    0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS_WRK
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG  ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;        // ProcessParameters 注意：这个后面多个\,不信测试或者看RtlGetCurrentDirectory_U函数源码。
    UNICODE_STRING DllPath;         // ProcessParameters
    UNICODE_STRING ImagePathName;   // ProcessParameters
    UNICODE_STRING CommandLine;     // ProcessParameters
    PVOID Environment;              // NtAllocateVirtualMemory

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;     // ProcessParameters
    UNICODE_STRING DesktopInfo;     // ProcessParameters
    UNICODE_STRING ShellInfo;       // ProcessParameters
    UNICODE_STRING RuntimeData;     // ProcessParameters
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[RTL_MAX_DRIVE_LETTERS];

    //经测试/观察可得：上面的数据不变，不同的系统会在下面添加成员。
    //所以这个结构只可用指针，不可嵌套用于结构，因为它的大小会变。
    //为了和微软网页上的那个结构避免重名，这个结构的后面加个WRK。
    //注意：前两个成员。
} RTL_USER_PROCESS_PARAMETERS_WRK, * PRTL_USER_PROCESS_PARAMETERS_WRK;


#if defined(_WIN64)
typedef struct _RTL_DRIVE_LETTER_CURDIR32
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING32 DosPath;
} RTL_DRIVE_LETTER_CURDIR32, * PRTL_DRIVE_LETTER_CURDIR32;

typedef struct _CURDIR32
{
    UNICODE_STRING32 DosPath;
    ULONG Handle;
} CURDIR32, * PCURDIR32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    ULONG ConsoleHandle;
    ULONG  ConsoleFlags;
    ULONG StandardInput;
    ULONG StandardOutput;
    ULONG StandardError;

    CURDIR32 CurrentDirectory;        // ProcessParameters
    UNICODE_STRING32 DllPath;         // ProcessParameters
    UNICODE_STRING32 ImagePathName;   // ProcessParameters
    UNICODE_STRING32 CommandLine;     // ProcessParameters
    ULONG Environment;              // NtAllocateVirtualMemory

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING32 WindowTitle;     // ProcessParameters
    UNICODE_STRING32 DesktopInfo;     // ProcessParameters
    UNICODE_STRING32 ShellInfo;       // ProcessParameters
    UNICODE_STRING32 RuntimeData;     // ProcessParameters
    RTL_DRIVE_LETTER_CURDIR32 CurrentDirectores[RTL_MAX_DRIVE_LETTERS];
} RTL_USER_PROCESS_PARAMETERS32, * PRTL_USER_PROCESS_PARAMETERS32;
#endif

#if defined(_X86_)
typedef struct _RTL_DRIVE_LETTER_CURDIR64
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING64 DosPath;
} RTL_DRIVE_LETTER_CURDIR64, * PRTL_DRIVE_LETTER_CURDIR64;

typedef struct _CURDIR64
{
    UNICODE_STRING64 DosPath;
    LONGLONG Handle;
} CURDIR64, * PCURDIR64;

typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    LONGLONG ConsoleHandle;
    ULONG  ConsoleFlags;
    LONGLONG StandardInput;
    LONGLONG StandardOutput;
    LONGLONG StandardError;

    CURDIR64 CurrentDirectory;        // ProcessParameters
    UNICODE_STRING64 DllPath;         // ProcessParameters
    UNICODE_STRING64 ImagePathName;   // ProcessParameters
    UNICODE_STRING64 CommandLine;     // ProcessParameters
    ULONGLONG Environment;              // NtAllocateVirtualMemory

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING64 WindowTitle;     // ProcessParameters
    UNICODE_STRING64 DesktopInfo;     // ProcessParameters
    UNICODE_STRING64 ShellInfo;       // ProcessParameters
    UNICODE_STRING64 RuntimeData;     // ProcessParameters
    RTL_DRIVE_LETTER_CURDIR64 CurrentDirectores[RTL_MAX_DRIVE_LETTERS];
} RTL_USER_PROCESS_PARAMETERS64, * PRTL_USER_PROCESS_PARAMETERS64;
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C PUCHAR PsGetProcessImageFileName(IN PEPROCESS Process); //未公开的函数。


//摘自WRK。
EXTERN_C
//NTKERNELAPI
PEJOB
PsGetProcessJob(
    __in PEPROCESS Process
);


//摘自：\wrk\WindowsResearchKernel-WRK\WRK-v1.2\public\internal\base\inc\zwapi.h
EXTERN_C
NTSTATUS ZwAdjustPrivilegesToken(IN HANDLE TokenHandle, 
                                 IN BOOLEAN DisableAllPrivileges,
                                 IN PTOKEN_PRIVILEGES NewState OPTIONAL,
                                 IN ULONG BufferLength OPTIONAL,
                                 OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL, 
                                 OUT PULONG ReturnLength);


//////////////////////////////////////////////////////////////////////////////////////////////////



typedef NTSTATUS(WINAPI * HandleProcess) (_In_ HANDLE UniqueProcessId, _In_opt_ PVOID Context);


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


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


EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
