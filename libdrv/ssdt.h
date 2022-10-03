#pragma once

#include "pch.h"
#include "Image.h"
#include "thread.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


#ifdef _X86_


#ifdef __cplusplus
extern "C" {
#endif


#pragma pack(1)
    typedef struct ServiceDescriptorEntry {
        ULONG_PTR * ServiceTableBase;
        unsigned int * ServiceCounterTableBase; //Used only in checked build
        unsigned int NumberOfServices;
        unsigned char * ParamTableBase;
    } ServiceDescriptorTableEntry_t, * PServiceDescriptorTableEntry_t;
#pragma pack()


    extern __declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]
#define SYSCALL_INDEX(_Function) (*(PULONG)((PUCHAR)_Function+1))
#define SYSCALL_END(_Function) (*(PULONG)((PUCHAR)_Function+12))


#ifdef __cplusplus
}
#endif


#endif 


#define SYSCALL_INDEX_64(_Function) (*(PULONG)((PUCHAR)_Function+3)) //这个暂时没用，有待实验和验证。


//////////////////////////////////////////////////////////////////////////////////////////////////


extern volatile ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryFn;
extern volatile ZwTerminateThread_pfn ZwTerminateThreadFn;


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


EXTERN_C SIZE_T GetZwRoutineAddress(PCSTR RoutineName);

void SetZwQueryVirtualMemoryAddress(_In_ ZwQueryVirtualMemory_PFN ZwQueryVirtualMemoryAddress);
void SetZwTerminateThreadAddress(_In_ ZwTerminateThread_pfn ZwTerminateThreadAddress);
void SetRtlCreateUserThreadAddress(_In_ RtlCreateUserThreadFn RtlCreateUserThreadAddress);



EXTERN_C_END
