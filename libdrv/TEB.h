#pragma once


#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
功能：获取TEB的办法：

注意：64位系统下的WOW64.

1.
void* _rdteb();//Reads the thread pointer register (IntR13) and returns its value, which is the base address of the current thread environment block (TEB).
void * __cdecl _rdtebex(void);
因为是编译器提供的指令，所以在用户和内核都可以使用。
包含在：\Include\um\winnt.h。

2.
用户层的函数：GetTebAddress，这是一个有源码的函数。
在WinDDK\7600.16385.1\inc\api\WDBGEXTS.H

3.
用户层的函数：NtCurrentTeb(void);
不同的环境下是不同的汇编指令。
这是一个宏/__inline的函数，所以这个函数是不会导出的。

4.
ZwQueryInformationThread的ThreadTebInformation。
用户和内核都可以使用。

5.
ZwQueryInformationThread的ThreadBasicInformation。
用户和内核都可以使用。

6.
PsGetCurrentThreadTeb。
不过需要：(NTDDI_VERSION >= NTDDI_WS03SP1)
也就是说XP没有导出此函数。
内核专用。
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentthreadteb

7.
PsGetThreadTeb
XP下已经导出。

WDK帮助文档上的定义，
typedef struct _TEB {
    BYTE Reserved1[1952];
    PVOID Reserved2[412];
    PVOID TlsSlots[64];
    BYTE Reserved3[8];
    PVOID Reserved4[26];
    PVOID ReservedForOle;
    PVOID Reserved5[4];
    PVOID TlsExpansionSlots;
} TEB,  *PTEB;
这个，同时和
https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb
上定义的一样。
但是有用的信息太少。

网络上竟然没有搜索到：
https://msdn.microsoft.com/en-us/library/ms686708(v=vs.85).aspx


0: kd> !teb
TEB at 7ffde000
    ExceptionList:        00a2ff68
    StackBase:            00a30000
    StackLimit:           00a22000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 7ffde000
    EnvironmentPointer:   00000000
    ClientId:             0000067c . 00000354
    RpcHandle:            00000000
    Tls Storage:          00000000
    PEB Address:          7ffd7000
    LastErrorValue:       0
    LastStatusValue:      0
    Count Owned Locks:    0
    HardErrorMode:        0
0: kd> dt _TEB
urlmon!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
   +0x040 Win32ThreadInfo  : Ptr32 Void
   +0x044 User32Reserved   : [26] Uint4B
   +0x0ac UserReserved     : [5] Uint4B
   +0x0c0 WOW32Reserved    : Ptr32 Void
   +0x0c4 CurrentLocale    : Uint4B
   +0x0c8 FpSoftwareStatusRegister : Uint4B
   +0x0cc SystemReserved1  : [54] Ptr32 Void
   +0x1a4 ExceptionCode    : Int4B
   +0x1a8 ActivationContextStackPointer : Ptr32 _ACTIVATION_CONTEXT_STACK
   +0x1ac SpareBytes1      : [36] UChar
   +0x1d0 TxFsContext      : Uint4B
   +0x1d4 GdiTebBatch      : _GDI_TEB_BATCH
   +0x6b4 RealClientId     : _CLIENT_ID
   +0x6bc GdiCachedProcessHandle : Ptr32 Void
   +0x6c0 GdiClientPID     : Uint4B
   +0x6c4 GdiClientTID     : Uint4B
   +0x6c8 GdiThreadLocalInfo : Ptr32 Void
   +0x6cc Win32ClientInfo  : [62] Uint4B
   +0x7c4 glDispatchTable  : [233] Ptr32 Void
   +0xb68 glReserved1      : [29] Uint4B
   +0xbdc glReserved2      : Ptr32 Void
   +0xbe0 glSectionInfo    : Ptr32 Void
   +0xbe4 glSection        : Ptr32 Void
   +0xbe8 glTable          : Ptr32 Void
   +0xbec glCurrentRC      : Ptr32 Void
   +0xbf0 glContext        : Ptr32 Void
   +0xbf4 LastStatusValue  : Uint4B
   +0xbf8 StaticUnicodeString : _UNICODE_STRING
   +0xc00 StaticUnicodeBuffer : [261] Wchar
   +0xe0c DeallocationStack : Ptr32 Void
   +0xe10 TlsSlots         : [64] Ptr32 Void
   +0xf10 TlsLinks         : _LIST_ENTRY
   +0xf18 Vdm              : Ptr32 Void
   +0xf1c ReservedForNtRpc : Ptr32 Void
   +0xf20 DbgSsReserved    : [2] Ptr32 Void
   +0xf28 HardErrorMode    : Uint4B
   +0xf2c Instrumentation  : [9] Ptr32 Void
   +0xf50 ActivityId       : _GUID  多一个。
   +0xf60 SubProcessTag    : Ptr32 Void
   +0xf64 EtwLocalData     : Ptr32 Void 多一个。
   +0xf68 EtwTraceData     : Ptr32 Void
   +0xf6c WinSockData      : Ptr32 Void
   +0xf70 GdiBatchCount    : Uint4B
   +0xf74 SpareBool0       : UChar
   +0xf75 SpareBool1       : UChar
   +0xf76 SpareBool2       : UChar
   +0xf77 IdealProcessor   : UChar 不一样了，定义的是TlsExpansionSlots。
   +0xf78 GuaranteedStackBytes : Uint4B
   +0xf7c ReservedForPerf  : Ptr32 Void
   +0xf80 ReservedForOle   : Ptr32 Void
   +0xf84 WaitingOnLoaderLock : Uint4B
   +0xf88 SavedPriorityState : Ptr32 Void
   +0xf8c SoftPatchPtr1    : Uint4B
   +0xf90 ThreadPoolData   : Ptr32 Void
   +0xf94 TlsExpansionSlots : Ptr32 Ptr32 Void
   +0xf98 ImpersonationLocale : Uint4B
   +0xf9c IsImpersonating  : Uint4B
   +0xfa0 NlsCache         : Ptr32 Void
   +0xfa4 pShimData        : Ptr32 Void
   +0xfa8 HeapVirtualAffinity : Uint4B
   +0xfac CurrentTransactionHandle : Ptr32 Void
   +0xfb0 ActiveFrame      : Ptr32 _TEB_ACTIVE_FRAME
   +0xfb4 FlsData          : Ptr32 Void
   +0xfb8 PreferredLanguages : Ptr32 Void
   +0xfbc UserPrefLanguages : Ptr32 Void
   +0xfc0 MergedPrefLanguages : Ptr32 Void
   +0xfc4 MuiImpersonation : Uint4B
   +0xfc8 CrossTebFlags    : Uint2B
   +0xfc8 SpareCrossTebBits : Pos 0, 16 Bits
   +0xfca SameTebFlags     : Uint2B
   +0xfca DbgSafeThunkCall : Pos 0, 1 Bit
   +0xfca DbgInDebugPrint  : Pos 1, 1 Bit
   +0xfca DbgHasFiberData  : Pos 2, 1 Bit
   +0xfca DbgSkipThreadAttach : Pos 3, 1 Bit
   +0xfca DbgWerInShipAssertCode : Pos 4, 1 Bit
   +0xfca DbgRanProcessInit : Pos 5, 1 Bit
   +0xfca DbgClonedThread  : Pos 6, 1 Bit
   +0xfca DbgSuppressDebugMsg : Pos 7, 1 Bit
   +0xfca RtlDisableUserStackWalk : Pos 8, 1 Bit
   +0xfca SpareSameTebBits : Pos 9, 7 Bits
   +0xfcc TxnScopeEnterCallback : Ptr32 Void
   +0xfd0 TxnScopeExitCallback : Ptr32 Void
   +0xfd4 TxnScopeContext  : Ptr32 Void
   +0xfd8 LockCount        : Uint4B
   +0xfdc ProcessRundown   : Uint4B
   +0xfe0 LastSwitchTime   : Uint8B
   +0xfe8 TotalSwitchOutTime : Uint8B
   +0xff0 WaitReasonBitMap : _LARGE_INTEGER

本文的一些结构摘自WRK。

made by correy
made at 2015.07.08.
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
其实NT_TIB已经在
\Windows Kits\10\Include\10.0.19041.0\km\ntddk.h
和
\Windows Kits\10\Include\10.0.19041.0\um\winnt.h
中定义，
还有NT_TIB32和NT_TIB64，甚至KUSER_SHARED_DATA。

NtCurrentTeb已经定义在winnt.h中，但是这个文件在：Windows Kits\10\Include\10.0.19041.0\um
https://docs.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-ntcurrentteb
这个上面也说明了，但是要包含这个文件，需要配置，如：
$(SDK_INC_PATH)
$(WDK_UM_INC_PATH)
$(CRT_IncludePath)
$(CppWinRT_IncludePath)
$(KIT_SHARED_INC_PATH_WDK)
$(WDK_UM_INC_PATH)
um即用户模式，不建议包含，而且有重复的定义，所以这里再去出来。
*/


/*
https://devblogs.microsoft.com/oldnewthing/20190418-00/?p=102428
typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    PVOID FiberData;
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB;
*/


/*
https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-a-stack-overflow

typedef struct _TEB {
    NT_TIB NtTib;
    PVOID  EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    .....
    PVOID DeallocationStack;
    .....
} TEB;

typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    .....
} NT_TIB;
*/


//////////////////////////////////////////////////////////////////////////////////////////////////


#define PEBTEB_PRIVATE_PASTE(x,y)       x##y
#define PEBTEB_PASTE(x,y)               PEBTEB_PRIVATE_PASTE(x,y)

#if defined(PEBTEB_BITS) /* This is defined by wow64t.h. */

#if PEBTEB_BITS == 32

#define PEBTEB_STRUCT(x)    PEBTEB_PASTE(x, 32) /* FOO32 */
#define PEBTEB_POINTER(x)   TYPE32(x) /* ULONG, defined in wow64t.h */

#elif PEBTEB_BITS == 64

#define PEBTEB_STRUCT(x)    PEBTEB_PASTE(x, 64) /* FOO64 */
#define PEBTEB_POINTER(x)   TYPE64(x) /* ULONGLONG, defined in wow64t.h */

#else

#error Unknown value for pebteb_bits (PEBTEB_BITS).

#endif

#else

//
// Declare and use regular native types.
//
#define PEBTEB_POINTER(x) x
#define PEBTEB_STRUCT(x)  x

#endif

#define STATIC_UNICODE_BUFFER_LENGTH 261
#define WIN32_CLIENT_INFO_LENGTH 62

#define TLS_MINIMUM_AVAILABLE 64    // winnt

typedef struct PEBTEB_STRUCT(_ACTIVATION_CONTEXT_STACK) {
    PEBTEB_POINTER(struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *) ActiveFrame;
    PEBTEB_STRUCT(LIST_ENTRY) FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} PEBTEB_STRUCT(ACTIVATION_CONTEXT_STACK), * PEBTEB_STRUCT(PACTIVATION_CONTEXT_STACK);


#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH {
    ULONG    Offset;
    ULONG_PTR HDC;
    ULONG    Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct PEBTEB_STRUCT(_TEB_ACTIVE_FRAME_CONTEXT) {
    ULONG Flags;
    PEBTEB_POINTER(PCSTR) FrameName;
} PEBTEB_STRUCT(TEB_ACTIVE_FRAME_CONTEXT), * PEBTEB_STRUCT(PTEB_ACTIVE_FRAME_CONTEXT);

typedef const PEBTEB_STRUCT(TEB_ACTIVE_FRAME_CONTEXT) * PEBTEB_STRUCT(PCTEB_ACTIVE_FRAME_CONTEXT);

typedef struct PEBTEB_STRUCT(_TEB_ACTIVE_FRAME) {
    ULONG Flags;
    PEBTEB_POINTER(struct _TEB_ACTIVE_FRAME *) Previous;
    PEBTEB_POINTER(PCTEB_ACTIVE_FRAME_CONTEXT) Context;
} PEBTEB_STRUCT(TEB_ACTIVE_FRAME), * PEBTEB_STRUCT(PTEB_ACTIVE_FRAME);


//typedef PVOID * PPVOID;

/* for searching
typedef struct _TEB
typedef struct _TEB32
typedef struct _TEB64
*/
typedef struct PEBTEB_STRUCT(_TEB) {
    PEBTEB_STRUCT(NT_TIB) NtTib;//这个结构倒是公开了，包括_NT_TIB32，_NT_TIB64。
    PEBTEB_POINTER(PVOID) EnvironmentPointer;
    PEBTEB_STRUCT(CLIENT_ID) ClientId;
    PEBTEB_POINTER(PVOID) ActiveRpcHandle;
    PEBTEB_POINTER(PVOID) ThreadLocalStoragePointer;
    PEBTEB_POINTER(PPEB) ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PEBTEB_POINTER(PVOID) CsrClientThread;
    PEBTEB_POINTER(PVOID) Win32ThreadInfo;          // PtiCurrent
    ULONG User32Reserved[26];       // user32.dll items
    ULONG UserReserved[5];          // Winsrv SwitchStack
    PEBTEB_POINTER(PVOID) WOW32Reserved;            // used by WOW
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister; // offset known by outsiders!
    PEBTEB_POINTER(PVOID) SystemReserved1[54];      // Used by FP emulator
    NTSTATUS ExceptionCode;         // for RaiseUserException
    // 4 bytes of padding here on native 64bit TEB and TEB64
    PEBTEB_POINTER(PACTIVATION_CONTEXT_STACK) ActivationContextStackPointer; // Fusion activation stack
#if (defined(PEBTEB_BITS) && (PEBTEB_BITS == 64)) || (!defined(PEBTEB_BITS) && defined(_WIN64))
    UCHAR SpareBytes1[28]; // native 64bit TEB and TEB64
#else
    UCHAR SpareBytes1[40]; // native 32bit TEB and TEB32
#endif
    PEBTEB_STRUCT(GDI_TEB_BATCH) GdiTebBatch;      // Gdi batching
    PEBTEB_STRUCT(CLIENT_ID) RealClientId;
    PEBTEB_POINTER(HANDLE) GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PEBTEB_POINTER(PVOID) GdiThreadLocalInfo;
    PEBTEB_POINTER(ULONG_PTR) Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH]; // User32 Client Info
    PEBTEB_POINTER(PVOID) glDispatchTable[233];     // OpenGL
    PEBTEB_POINTER(ULONG_PTR) glReserved1[29];      // OpenGL
    PEBTEB_POINTER(PVOID) glReserved2;              // OpenGL
    PEBTEB_POINTER(PVOID) glSectionInfo;            // OpenGL
    PEBTEB_POINTER(PVOID) glSection;                // OpenGL
    PEBTEB_POINTER(PVOID) glTable;                  // OpenGL
    PEBTEB_POINTER(PVOID) glCurrentRC;              // OpenGL
    PEBTEB_POINTER(PVOID) glContext;                // OpenGL
    ULONG LastStatusValue;
    PEBTEB_STRUCT(UNICODE_STRING) StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];
    PEBTEB_POINTER(PVOID) DeallocationStack;
    PEBTEB_POINTER(PVOID) TlsSlots[TLS_MINIMUM_AVAILABLE];
    PEBTEB_STRUCT(LIST_ENTRY) TlsLinks;
    PEBTEB_POINTER(PVOID) Vdm;
    PEBTEB_POINTER(PVOID) ReservedForNtRpc;
    PEBTEB_POINTER(PVOID) DbgSsReserved[2];
    ULONG HardErrorMode;
    PEBTEB_POINTER(PVOID) Instrumentation[14];
    PEBTEB_POINTER(PVOID) SubProcessTag;
    PEBTEB_POINTER(PVOID) EtwTraceData;
    PEBTEB_POINTER(PVOID) WinSockData;              // WinSock
    ULONG GdiBatchCount;
    BOOLEAN InDbgPrint;
    BOOLEAN FreeStackOnTermination;
    BOOLEAN HasFiberData;
    BOOLEAN IdealProcessor;
    ULONG GuaranteedStackBytes;
    PEBTEB_POINTER(PVOID) ReservedForPerf;
    PEBTEB_POINTER(PVOID) ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PEBTEB_POINTER(ULONG_PTR) SparePointer1;
    PEBTEB_POINTER(ULONG_PTR) SoftPatchPtr1;
    PEBTEB_POINTER(ULONG_PTR) SoftPatchPtr2;
    PEBTEB_POINTER(PVOID *) TlsExpansionSlots;
#if (defined(_WIN64) && !defined(PEBTEB_BITS)) || ((defined(_WIN64) || defined(_X86_)) && defined(PEBTEB_BITS) && PEBTEB_BITS == 64)
    //
    // These are in native Win64 TEB, Win64 TEB64, and x86 TEB64.
    //
    PEBTEB_POINTER(PVOID) DeallocationBStore;
    PEBTEB_POINTER(PVOID) BStoreLimit;
#endif    
    LCID ImpersonationLocale;       // Current locale of impersonated user
    ULONG IsImpersonating;          // Thread impersonation Status
    PEBTEB_POINTER(PVOID) NlsCache;                 // NLS thread cache
    PEBTEB_POINTER(PVOID) pShimData;                // Per thread data used in the shim
    ULONG HeapVirtualAffinity;
    PEBTEB_POINTER(HANDLE) CurrentTransactionHandle;// reserved for TxF transaction context
    PEBTEB_POINTER(PTEB_ACTIVE_FRAME) ActiveFrame;
    PEBTEB_POINTER(PVOID) FlsData;
    BOOLEAN SafeThunkCall;
    BOOLEAN BooleanSpare[3];

} PEBTEB_STRUCT(TEB), * PEBTEB_STRUCT(PTEB);


//////////////////////////////////////////////////////////////////////////////////////////////////
