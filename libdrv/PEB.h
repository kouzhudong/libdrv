#pragma once


#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//https://msdn.microsoft.com/en-us/library/windows/desktop/aa813741(v=vs.85).aspx
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


//https://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx
typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


//Windows Kits\8.0\Include\um\winternl.h
typedef
VOID
(NTAPI * PPS_POST_PROCESS_INIT_ROUTINE) (
    VOID
    );


#if defined(_WIN64) //defined(_AMD64_) || defined(_IA64_) //

//https://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA Ldr;// LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB, * PPEB;

#else 

//https://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx
typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    BYTE                          Reserved4[104];
    PVOID                         Reserved5[52];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved6[128];
    PVOID                         Reserved7[1];
    ULONG                         SessionId;
} PEB, * PPEB;

#endif


//////////////////////////////////////////////////////////////////////////////////////////////////
//PEB32的定义。


//Windows Kits\8.0\Include\um\winternl.h
typedef
VOID
(NTAPI * PPS_POST_PROCESS_INIT_ROUTINE) (
    VOID
    );


#define WOW64_POINTER(Type) ULONG
#define GDI_HANDLE_BUFFER_SIZE32 34
#define FLS_MAXIMUM_AVAILABLE 128
typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];

#define GDI_HANDLE_BUFFER_SIZE32  34
#define GDI_HANDLE_BUFFER_SIZE64  60

#if !defined(_AMD64_)
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE      GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK * Next;
    ULONG Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

#define PEBTEB_POINTER(x) x
#define PEBTEB_STRUCT(x)  x
#define PPVOID PVOID *


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

// Declare and use regular native types.
#define PEBTEB_POINTER(x) x
#define PEBTEB_STRUCT(x)  x

#endif


/* for searching
typedef struct _PEB
typedef struct _PEB32
typedef struct _PEB64
摘自：\WRK-v1.2\public\sdk\inc\pebteb.h
*/
#pragma pack(push,1)
//typedef struct PEBTEB_STRUCT(_PEB) {
typedef struct _PEB32
{
    BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
    BOOLEAN ReadImageFileExecOptions;   //
    BOOLEAN BeingDebugged;              //
    union
    {
        BOOLEAN BitField;                  //
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN SpareBits : 7;
        };
    };
    PEBTEB_POINTER(/*HANDLE*/ unsigned int) Mutant;      // INITIAL_PEB structure is also updated.

    PEBTEB_POINTER(/*PVOID*/ unsigned int) ImageBaseAddress;
    PEBTEB_POINTER( /*PPEB_LDR_DATA PEB_LDR_DATA_WOW*/ unsigned int) Ldr;
    PEBTEB_POINTER(struct _RTL_USER_PROCESS_PARAMETERS *) ProcessParameters;
    PEBTEB_POINTER(PVOID) SubSystemData;
    PEBTEB_POINTER(PVOID) ProcessHeap;
    PEBTEB_POINTER(struct _RTL_CRITICAL_SECTION *) FastPebLock;
    PEBTEB_POINTER(PVOID) AtlThunkSListPtr;     // Used only for AMD64
    PEBTEB_POINTER(PVOID) SparePtr2;
    ULONG EnvironmentUpdateCount;
    PEBTEB_POINTER(PVOID) KernelCallbackTable;
    ULONG SystemReserved[1];
    ULONG SpareUlong;
    PEBTEB_POINTER(PPEB_FREE_BLOCK) FreeList;
    ULONG TlsExpansionCounter;
    PEBTEB_POINTER(PVOID) TlsBitmap;
    ULONG TlsBitmapBits[2];         // TLS_MINIMUM_AVAILABLE bits
    PEBTEB_POINTER(PVOID) ReadOnlySharedMemoryBase;
    PEBTEB_POINTER(PVOID) ReadOnlySharedMemoryHeap;
    PEBTEB_POINTER(PPVOID) ReadOnlyStaticServerData;
    PEBTEB_POINTER(PVOID) AnsiCodePageData;
    PEBTEB_POINTER(PVOID) OemCodePageData;
    PEBTEB_POINTER(PVOID) UnicodeCaseTableData;

    //
    // Useful information for LdrpInitialize
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    //
    // Passed up from MmCreatePeb from Session Manager registry key
    //

    LARGE_INTEGER CriticalSectionTimeout;
    PEBTEB_POINTER(SIZE_T) HeapSegmentReserve;
    PEBTEB_POINTER(SIZE_T) HeapSegmentCommit;
    PEBTEB_POINTER(SIZE_T) HeapDeCommitTotalFreeThreshold;
    PEBTEB_POINTER(SIZE_T) HeapDeCommitFreeBlockThreshold;

    //
    // Where heap manager keeps track of all heaps created for a process
    // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
    // to point to the first free byte after the PEB and MaximumNumberOfHeaps
    // is computed from the page size used to hold the PEB, less the fixed
    // size of this data structure.
    //

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PEBTEB_POINTER(PPVOID) ProcessHeaps;

    //
    //
    PEBTEB_POINTER(PVOID) GdiSharedHandleTable;
    PEBTEB_POINTER(PVOID) ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PEBTEB_POINTER(struct _RTL_CRITICAL_SECTION *) LoaderLock;

    //
    // Following fields filled in by MmCreatePeb from system values and/or
    // image header.
    //

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    PEBTEB_POINTER(ULONG_PTR) ImageProcessAffinityMask;
    PEBTEB_STRUCT(GDI_HANDLE_BUFFER) GdiHandleBuffer;
    PEBTEB_POINTER(PPS_POST_PROCESS_INIT_ROUTINE) PostProcessInitRoutine;

    PEBTEB_POINTER(PVOID) TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];   // TLS_EXPANSION_SLOTS bits

    //
    // Id of the Hydra session in which this process is running
    //
    ULONG SessionId;

    //
    // Filled in by LdrpInstallAppcompatBackend
    //
    ULARGE_INTEGER AppCompatFlags;

    //
    // ntuser appcompat flags
    //
    ULARGE_INTEGER AppCompatFlagsUser;

    //
    // Filled in by LdrpInstallAppcompatBackend
    //
    PEBTEB_POINTER(PVOID) pShimData;

    //
    // Filled in by LdrQueryImageFileExecutionOptions
    //
    PEBTEB_POINTER(PVOID) AppCompatInfo;

    //
    // Used by GetVersionExW as the szCSDVersion string
    //
    PEBTEB_STRUCT(UNICODE_STRING) CSDVersion;

    //
    // Fusion stuff
    //
    PEBTEB_POINTER(const struct _ACTIVATION_CONTEXT_DATA *) ActivationContextData;
    PEBTEB_POINTER(struct _ASSEMBLY_STORAGE_MAP *) ProcessAssemblyStorageMap;
    PEBTEB_POINTER(const struct _ACTIVATION_CONTEXT_DATA *) SystemDefaultActivationContextData;
    PEBTEB_POINTER(struct _ASSEMBLY_STORAGE_MAP *) SystemAssemblyStorageMap;

    //
    // Enforced minimum initial commit stack
    //
    PEBTEB_POINTER(SIZE_T) MinimumStackCommit;

    //
    // Fiber local storage.
    //

    PEBTEB_POINTER(PPVOID) FlsCallback;
    PEBTEB_STRUCT(LIST_ENTRY) FlsListHead;
    PEBTEB_POINTER(PVOID) FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;
    //} PEBTEB_STRUCT(PEB), * PEBTEB_STRUCT(PPEB);
} PEB32, * PPEB32;


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
摘自：\wrk\WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\inc\ps.h
此函数在XP 32上就已经导出，应该可以放心使用。
或者ZwQueryInformationProcess 的 ProcessBasicInformation.
*/
EXTERN_C
//NTKERNELAPI 
PPEB PsGetProcessPeb(__in PEPROCESS Process);


//////////////////////////////////////////////////////////////////////////////////////////////////
