/*
本文主要收集CPU的一些信息。

本文的大部分代码在驱动和应用层都可使用。

凡是有printf_s的应该都可以在应用层使用。
*/

#pragma once

#include "pch.h"

class cpu
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


//自己添加。
#define printf_s DbgPrint


//////////////////////////////////////////////////////////////////////////////////////////////////


//结构可以再修改。
union IA32_VMX_PINBASED_CTLS
{
    unsigned __int64 all;
    struct
    {
        unsigned allowed_0_settings : 32;//!< [0:31]
        unsigned allowed_1_settings : 32;//!< [32:63]
    } fields;
};


//////////////////////////////////////////////////////////////////////////////////////////////////


//结构可以再修改。
union IA32_VMX_PROCBASED_CTLS
{
    unsigned __int64 all;
    struct
    {
        unsigned allowed_0_settings : 32;//!< [0:31]
        unsigned allowed_1_settings : 32;//!< [32:63]
    } fields;
};


//////////////////////////////////////////////////////////////////////////////////////////////////


//结构可以再修改。
union IA32_VMX_PROCBASED_CTLS2
{
    unsigned __int64 all;
    struct
    {
        unsigned allowed_0_settings : 32;//!< [0:31]
        unsigned allowed_1_settings : 32;//!< [32:63]
    } fields;
};


//////////////////////////////////////////////////////////////////////////////////////////////////


#define IA32_THERM_STATUS         0x19C
#define MSR_TEMPERATURE_TARGET    0x1A2


//////////////////////////////////////////////////////////////////////////////////////////////////


union BASIC_VMX_INFORMATION
{
    unsigned __int64 all;
    struct
    {
        unsigned vmcs_revision_identifier : 31;//!< [0:30]
        unsigned reserved1 : 1;                //!< [31]
        unsigned region_size : 13;             //!< [32:44]
        unsigned reserved2 : 3;                //!< [45:47]
        unsigned supported_32 : 1;             //!< [48]
        unsigned supported_dual_moniter : 1;   //!< [49]
        unsigned memory_type : 4;              //!< [50:53] 大部分等于6
        unsigned vm_exit_report : 1;           //!< [54]
        unsigned vmx_capability_hint : 1;      //!< [55]
        unsigned reserved3 : 8;                //!< [56:63]
    } fields;
};


//////////////////////////////////////////////////////////////////////////////////////////////////


#define IA32_VMX_BASIC         0x480


//还是定义个结构吧，省了麻烦的位与的计算。
typedef struct  _MSR_IA32_VMX_BASIC {
    unsigned VMCS_RID : 31; //Bits 30:0 contain the 31-bit VMCS revision identifier used by the processor.
    unsigned reserved1 : 1; //Bit 31 is always 0.
    unsigned number : 13; //Bits 44:32 report the number of bytes that software should allocate for the VMXON region and any VMCS region.
    unsigned reserved2 : 3; //The values of bits 47:45 and bits 63:56 are reserved and are read as 0.
    unsigned width : 1; //Bit 48 indicates the width of the physical addresses that may be used for the VMXON region, each VMCS, 
    //and data structures referenced by pointers in a VMCS(I / O bitmaps, virtual - APIC page, MSR areas for VMX transitions).
    unsigned DMT_SMI_SMM : 1; //If bit 49 is read as 1, the logical processor supports the dual - monitor treatment of system - management interrupts and system - management mode.
    unsigned memory_type : 4; //Bits 53:50 report the memory type that should be used for the VMCS, for data structures referenced by
    //pointers in the VMCS(I / O bitmaps, virtual - APIC page, MSR areas for VMX transitions), and for the MSEG header.
    unsigned INS_OUTS : 1; //If bit 54 is read as 1, the logical processor reports information in the VM-exit instruction-information field on
    // VM exits due to execution of the INS and OUTS instructions.This reporting is done only if this bit is read as 1.
    unsigned IA32_VMX_TRUE : 1; //Bit 55 is read as 1 if any VMX controls that default to 1 may be cleared to 0.
    unsigned reserved3 : 8; //The values of bits 47:45 and bits 63:56 are reserved and are read as 0.
    //以上数字相加为64.
} MSR_IA32_VMX_BASIC, * PMSR_IA32_VMX_BASIC;


//////////////////////////////////////////////////////////////////////////////////////////////////


//结构可以再修改。
union IA32_VMX_EPT_VPID_CAP
{
    unsigned __int64 all;
    struct {
        unsigned support_execute_only_pages : 1;                        //!< [0]
        unsigned reserved1 : 5;                                         //!< [1:5]
        unsigned support_page_walk_length4 : 1;                         //!< [6]
        unsigned reserved2 : 1;                                         //!< [7]
        unsigned support_uncacheble_memory_type : 1;                    //!< [8]
        unsigned reserved3 : 5;                                         //!< [9:13]
        unsigned support_write_back_memory_type : 1;                    //!< [14]
        unsigned reserved4 : 1;                                         //!< [15]
        unsigned support_pde_2mb_pages : 1;                             //!< [16]
        unsigned support_pdpte_1_gb_pages : 1;                          //!< [17]
        unsigned reserved5 : 2;                                         //!< [18:19]
        unsigned support_invept : 1;                                    //!< [20]
        unsigned support_accessed_and_dirty_flag : 1;                   //!< [21]
        unsigned reserved6 : 3;                                         //!< [22:24]
        unsigned support_single_context_invept : 1;                     //!< [25]
        unsigned support_all_context_invept : 1;                        //!< [26]
        unsigned reserved7 : 5;                                         //!< [27:31]
        unsigned support_invvpid : 1;                                   //!< [32]
        unsigned reserved8 : 7;                                         //!< [33:39]
        unsigned support_individual_address_invvpid : 1;                //!< [40]
        unsigned support_single_context_invvpid : 1;                    //!< [41]
        unsigned support_all_context_invvpid : 1;                       //!< [42]
        unsigned support_single_context_retaining_globals_invvpid : 1;  //!< [43]
        unsigned reserved9 : 20;                                        //!< [44:63]
    } fields;
};


#define IA32_VMX_PROCBASED_CTLS_MSR 0x482
#define IA32_VMX_PROCBASED_CTLS2_MSR 0x48B
#define IA32_VMX_EPT_VPID_CAP_MSR 0x48C


//////////////////////////////////////////////////////////////////////////////////////////////////


//一下结构摘自：WRK，注释来自INTEL。


#ifdef _AMD64_


// Structure of Intel deterministic cache information returned by CPUID instruction
// Windows Kits\10\Include\10.0.19041.0\km\wdm.h
typedef enum _INTEL_CACHE_TYPE {//Bits 04-00: Cache Type Field
    IntelCacheNull,       //0 = Null - No more caches
    IntelCacheData,       //1 = Data Cache
    IntelCacheInstruction,//2 = Instruction Cache
    IntelCacheUnified,    //3 = Unified Cache
    IntelCacheRam,        //4-31 = Reserved
    IntelCacheTrace
} INTEL_CACHE_TYPE;


// Windows Kits\10\Include\10.0.19041.0\km\wdm.h
typedef union INTEL_CACHE_INFO_EAX {
    ULONG Ulong;
    struct {
        INTEL_CACHE_TYPE Type : 5; //Bits 04-00: Cache Type Field
        ULONG Level : 3;           //Bits 07-05: Cache Level (starts at 1)
        ULONG SelfInitializing : 1;//Bit 08: Self Initializing cache level (does not need SW initialization)
        ULONG FullyAssociative : 1;//Bit 09: Fully Associative cache
        ULONG Reserved : 4;        //Bits 13-10: Reserved
        ULONG ThreadsSharing : 12; //Bits 25-14: Maximum number of addressable IDs for logical processors sharing this cache**, ***
        ULONG ProcessorCores : 6;  //Bits 31-26: Maximum number of addressable IDs for processor cores in the physical package**, ****, *****
    };
} INTEL_CACHE_INFO_EAX, * PINTEL_CACHE_INFO_EAX;


// Windows Kits\10\Include\10.0.19041.0\km\wdm.h
typedef union INTEL_CACHE_INFO_EBX {
    ULONG Ulong;
    struct {
        ULONG LineSize : 12;     //Bits 11-00: L = System Coherency Line Size**
        ULONG Partitions : 10;   //Bits 21-12: P = Physical Line partitions**
        ULONG Associativity : 10;//Bits 31-22: W = Ways of associativity**
    };
} INTEL_CACHE_INFO_EBX, * PINTEL_CACHE_INFO_EBX;


#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


VOID DisSmep();


EXTERN_C_END
