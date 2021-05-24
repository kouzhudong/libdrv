#include "cpu.h"


#pragma warning(disable:6328)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////


const char * szFeatures[] =
{
    "x87 FPU On Chip",
    "Virtual-8086 Mode Enhancement",
    "Debugging Extensions",
    "Page Size Extensions",
    "Time Stamp Counter",
    "RDMSR and WRMSR Support",
    "Physical Address Extensions",
    "Machine Check Exception",
    "CMPXCHG8B Instruction",
    "APIC On Chip",
    "Unknown1",
    "SYSENTER and SYSEXIT",
    "Memory Type Range Registers",
    "PTE Global Bit",
    "Machine Check Architecture",
    "Conditional Move/Compare Instruction",
    "Page Attribute Table",
    "36-bit Page Size Extension",
    "Processor Serial Number",
    "CFLUSH Extension",
    "Unknown2",
    "Debug Store",
    "Thermal Monitor and Clock Ctrl",
    "MMX Technology",
    "FXSAVE/FXRSTOR",
    "SSE Extensions",
    "SSE2 Extensions",
    "Self Snoop",
    "Multithreading Technology",
    "Thermal Monitor",
    "Unknown4",
    "Pending Break Enable"
};


NTSTATUS CPUIDTTEST()
/*
标题：内核中的CPUID。

CPUID这个指令很有用，如查看：CPU微码，虚拟化等。
注意很旧的CPU不支持：http://correy.webs.com/articles/computer/asm/cpu_microcode.asm.txt
如此重要的指令，微软岂能不支持。
尽管X64不支持内联汇编，但也有替代的办法对付此特别有用的指令。
如：http://msdn.microsoft.com/en-us/library/26td21ds.aspx

本文参考：http://msdn.microsoft.com/zh-cn/library/hskdteyh(v=vs.110).aspx
在X86和X64的Windows系统上测试通过。

made by correy
made at 2014.08.20
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    char CPUString[0x20];
    char CPUBrandString[0x40];
    int CPUInfo[4] = {-1};
    int nSteppingID = 0;
    int nModel = 0;
    int nFamily = 0;
    int nProcessorType = 0;
    int nExtendedmodel = 0;
    int nExtendedfamily = 0;
    int nBrandIndex = 0;
    int nCLFLUSHcachelinesize = 0;
    int nLogicalProcessors = 0;
    int nAPICPhysicalID = 0;
    int nFeatureInfo = 0;
    int nCacheLineSize = 0;
    int nL2Associativity = 0;
    int nCacheSizeK = 0;
    int nPhysicalAddress = 0;
    int nVirtualAddress = 0;
    //int nRet = 0;

    int nCores = 0;
    int nCacheType = 0;
    int nCacheLevel = 0;
    int nMaxThread = 0;
    int nSysLineSize = 0;
    int nPhysicalLinePartitions = 0;
    int nWaysAssociativity = 0;
    int nNumberSets = 0;

    unsigned    nIds, nExIds, i;

    bool    bSSE3Instructions = false;
    bool    bMONITOR_MWAIT = false;
    bool    bCPLQualifiedDebugStore = false;
    bool    bVirtualMachineExtensions = false;
    bool    bEnhancedIntelSpeedStepTechnology = false;
    bool    bThermalMonitor2 = false;
    bool    bSupplementalSSE3 = false;
    bool    bL1ContextID = false;
    bool    bCMPXCHG16B = false;
    bool    bxTPRUpdateControl = false;
    bool    bPerfDebugCapabilityMSR = false;
    bool    bSSE41Extensions = false;
    bool    bSSE42Extensions = false;
    bool    bPOPCNT = false;

    bool    bMultithreading = false;

    bool    bLAHF_SAHFAvailable = false;
    bool    bCmpLegacy = false;
    bool    bSVM = false;
    bool    bExtApicSpace = false;
    bool    bAltMovCr8 = false;
    bool    bLZCNT = false;
    bool    bSSE4A = false;
    bool    bMisalignedSSE = false;
    bool    bPREFETCH = false;
    bool    bSKINITandDEV = false;
    bool    bSYSCALL_SYSRETAvailable = false;
    bool    bExecuteDisableBitAvailable = false;
    bool    bMMXExtensions = false;
    bool    bFFXSR = false;
    bool    b1GBSupport = false;
    bool    bRDTSCP = false;
    bool    b64Available = false;
    bool    b3DNowExt = false;
    bool    b3DNow = false;
    bool    bNestedPaging = false;
    bool    bLBRVisualization = false;
    bool    bFP128 = false;
    bool    bMOVOptimization = false;

    bool    bSelfInit = false;
    bool    bFullyAssociative = false;

    // __cpuid with an InfoType argument of 0 returns the number of valid Ids in CPUInfo[0] and 
    // the CPU identification string in the other three array elements.
    // The CPU identification string is not in linear order. 
    // The code below arranges the information in a human readable form.

    /*
    这行指令对应的汇编代码为：
    X86:
    180 test.c               f88902e5 8d758c          lea     esi,[ebp-74h]
    180 test.c               f88902e8 33c0            xor     eax,eax
    180 test.c               f88902ea 33c9            xor     ecx,ecx
    180 test.c               f88902ec 0fa2            cpuid
    180 test.c               f88902ee 8906            mov     dword ptr [esi],eax
    180 test.c               f88902f0 895e04          mov     dword ptr [esi+4],ebx
    180 test.c               f88902f3 894e08          mov     dword ptr [esi+8],ecx
    180 test.c               f88902f6 89560c          mov     dword ptr [esi+0Ch],edx

    X64:
    167 test.c               fffff880`06b79300 33c0            xor     eax,eax
    167 test.c               fffff880`06b79302 33c9            xor     ecx,ecx
    167 test.c               fffff880`06b79304 0fa2            cpuid
    167 test.c               fffff880`06b79306 488dbc24d0010000 lea     rdi,[rsp+1D0h]
    167 test.c               fffff880`06b7930e 8907            mov     dword ptr [rdi],eax
    167 test.c               fffff880`06b79310 895f04          mov     dword ptr [rdi+4],ebx
    167 test.c               fffff880`06b79313 894f08          mov     dword ptr [rdi+8],ecx
    167 test.c               fffff880`06b79316 89570c          mov     dword ptr [rdi+0Ch],edx
    */
    __cpuid(CPUInfo, 0);
    nIds = CPUInfo[0];
    memset(CPUString, 0, sizeof(CPUString));
    *((int *)CPUString) = CPUInfo[1];
    *((int *)(CPUString + 4)) = CPUInfo[3];
    *((int *)(CPUString + 8)) = CPUInfo[2];

    // Get the information associated with each valid Id
    for (i = 0; i <= nIds; ++i) {
        __cpuid(CPUInfo, i);
        printf_s("\nFor InfoType %d\n", i);
        printf_s("CPUInfo[0] = 0x%x\n", CPUInfo[0]);
        printf_s("CPUInfo[1] = 0x%x\n", CPUInfo[1]);
        printf_s("CPUInfo[2] = 0x%x\n", CPUInfo[2]);
        printf_s("CPUInfo[3] = 0x%x\n", CPUInfo[3]);

        // Interpret CPU feature information.
        if (i == 1) {
            nSteppingID = CPUInfo[0] & 0xf;
            nModel = (CPUInfo[0] >> 4) & 0xf;
            nFamily = (CPUInfo[0] >> 8) & 0xf;
            nProcessorType = (CPUInfo[0] >> 12) & 0x3;
            nExtendedmodel = (CPUInfo[0] >> 16) & 0xf;
            nExtendedfamily = (CPUInfo[0] >> 20) & 0xff;
            nBrandIndex = CPUInfo[1] & 0xff;
            nCLFLUSHcachelinesize = ((CPUInfo[1] >> 8) & 0xff) * 8;
            nLogicalProcessors = ((CPUInfo[1] >> 16) & 0xff);
            nAPICPhysicalID = (CPUInfo[1] >> 24) & 0xff;
            bSSE3Instructions = (CPUInfo[2] & 0x1) || false;
            bMONITOR_MWAIT = (CPUInfo[2] & 0x8) || false;
            bCPLQualifiedDebugStore = (CPUInfo[2] & 0x10) || false;
            bVirtualMachineExtensions = (CPUInfo[2] & 0x20) || false;
            bEnhancedIntelSpeedStepTechnology = (CPUInfo[2] & 0x80) || false;
            bThermalMonitor2 = (CPUInfo[2] & 0x100) || false;
            bSupplementalSSE3 = (CPUInfo[2] & 0x200) || false;
            bL1ContextID = (CPUInfo[2] & 0x300) || false;
            bCMPXCHG16B = (CPUInfo[2] & 0x2000) || false;
            bxTPRUpdateControl = (CPUInfo[2] & 0x4000) || false;
            bPerfDebugCapabilityMSR = (CPUInfo[2] & 0x8000) || false;
            bSSE41Extensions = (CPUInfo[2] & 0x80000) || false;
            bSSE42Extensions = (CPUInfo[2] & 0x100000) || false;
            bPOPCNT = (CPUInfo[2] & 0x800000) || false;
            nFeatureInfo = CPUInfo[3];
            bMultithreading = (nFeatureInfo & (1 << 28)) || false;
        }
    }

    // Calling __cpuid with 0x80000000 as the InfoType argument
    // gets the number of valid extended IDs.
    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    memset(CPUBrandString, 0, sizeof(CPUBrandString));

    // Get the information associated with each extended ID.
    for (i = 0x80000000; i <= nExIds; ++i) {
        __cpuid(CPUInfo, i);
        printf_s("\nFor InfoType %x\n", i);
        printf_s("CPUInfo[0] = 0x%x\n", CPUInfo[0]);
        printf_s("CPUInfo[1] = 0x%x\n", CPUInfo[1]);
        printf_s("CPUInfo[2] = 0x%x\n", CPUInfo[2]);
        printf_s("CPUInfo[3] = 0x%x\n", CPUInfo[3]);

        if (i == 0x80000001) {
            bLAHF_SAHFAvailable = (CPUInfo[2] & 0x1) || false;
            bCmpLegacy = (CPUInfo[2] & 0x2) || false;
            bSVM = (CPUInfo[2] & 0x4) || false;
            bExtApicSpace = (CPUInfo[2] & 0x8) || false;
            bAltMovCr8 = (CPUInfo[2] & 0x10) || false;
            bLZCNT = (CPUInfo[2] & 0x20) || false;
            bSSE4A = (CPUInfo[2] & 0x40) || false;
            bMisalignedSSE = (CPUInfo[2] & 0x80) || false;
            bPREFETCH = (CPUInfo[2] & 0x100) || false;
            bSKINITandDEV = (CPUInfo[2] & 0x1000) || false;
            bSYSCALL_SYSRETAvailable = (CPUInfo[3] & 0x800) || false;
            bExecuteDisableBitAvailable = (CPUInfo[3] & 0x10000) || false;
            bMMXExtensions = (CPUInfo[3] & 0x40000) || false;
            bFFXSR = (CPUInfo[3] & 0x200000) || false;
            b1GBSupport = (CPUInfo[3] & 0x400000) || false;
            bRDTSCP = (CPUInfo[3] & 0x8000000) || false;
            b64Available = (CPUInfo[3] & 0x20000000) || false;
            b3DNowExt = (CPUInfo[3] & 0x40000000) || false;
            b3DNow = (CPUInfo[3] & 0x80000000) || false;
        }

        // Interpret CPU brand string and cache information.
        if (i == 0x80000002)
            memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
        else if (i == 0x80000003)
            memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
        else if (i == 0x80000004)
            memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
        else if (i == 0x80000006) {
            nCacheLineSize = CPUInfo[2] & 0xff;
            nL2Associativity = (CPUInfo[2] >> 12) & 0xf;
            nCacheSizeK = (CPUInfo[2] >> 16) & 0xffff;
        } else if (i == 0x80000008) {
            nPhysicalAddress = CPUInfo[0] & 0xff;
            nVirtualAddress = (CPUInfo[0] >> 8) & 0xff;
        } else if (i == 0x8000000A) {
            bNestedPaging = (CPUInfo[3] & 0x1) || false;
            bLBRVisualization = (CPUInfo[3] & 0x2) || false;
        } else if (i == 0x8000001A) {
            bFP128 = (CPUInfo[0] & 0x1) || false;
            bMOVOptimization = (CPUInfo[0] & 0x2) || false;
        }
    }

    // Display all the information in user-friendly format.

    printf_s("\n\nCPU String: %s\n", CPUString);

    if (nIds >= 1) {
        if (nSteppingID)
            printf_s("Stepping ID = %d\n", nSteppingID);
        if (nModel)
            printf_s("Model = %d\n", nModel);
        if (nFamily)
            printf_s("Family = %d\n", nFamily);
        if (nProcessorType)
            printf_s("Processor Type = %d\n", nProcessorType);
        if (nExtendedmodel)
            printf_s("Extended model = %d\n", nExtendedmodel);
        if (nExtendedfamily)
            printf_s("Extended family = %d\n", nExtendedfamily);
        if (nBrandIndex)
            printf_s("Brand Index = %d\n", nBrandIndex);
        if (nCLFLUSHcachelinesize)
            printf_s("CLFLUSH cache line size = %d\n", nCLFLUSHcachelinesize);
        if (bMultithreading && (nLogicalProcessors > 0))
            printf_s("Logical Processor Count = %d\n", nLogicalProcessors);
        if (nAPICPhysicalID)
            printf_s("APIC Physical ID = %d\n", nAPICPhysicalID);

        if (nFeatureInfo || bSSE3Instructions ||
            bMONITOR_MWAIT || bCPLQualifiedDebugStore ||
            bVirtualMachineExtensions || bEnhancedIntelSpeedStepTechnology ||
            bThermalMonitor2 || bSupplementalSSE3 || bL1ContextID ||
            bCMPXCHG16B || bxTPRUpdateControl || bPerfDebugCapabilityMSR ||
            bSSE41Extensions || bSSE42Extensions || bPOPCNT ||
            bLAHF_SAHFAvailable || bCmpLegacy || bSVM ||
            bExtApicSpace || bAltMovCr8 ||
            bLZCNT || bSSE4A || bMisalignedSSE ||
            bPREFETCH || bSKINITandDEV || bSYSCALL_SYSRETAvailable ||
            bExecuteDisableBitAvailable || bMMXExtensions || bFFXSR || b1GBSupport ||
            bRDTSCP || b64Available || b3DNowExt || b3DNow || bNestedPaging ||
            bLBRVisualization || bFP128 || bMOVOptimization) {
            printf_s("\nThe following features are supported:\n");

            if (bSSE3Instructions)
                printf_s("\tSSE3\n");
            if (bMONITOR_MWAIT)
                printf_s("\tMONITOR/MWAIT\n");
            if (bCPLQualifiedDebugStore)
                printf_s("\tCPL Qualified Debug Store\n");
            if (bVirtualMachineExtensions)
                printf_s("\tVirtual Machine Extensions\n");
            if (bEnhancedIntelSpeedStepTechnology)
                printf_s("\tEnhanced Intel SpeedStep Technology\n");
            if (bThermalMonitor2)
                printf_s("\tThermal Monitor 2\n");
            if (bSupplementalSSE3)
                printf_s("\tSupplemental Streaming SIMD Extensions 3\n");
            if (bL1ContextID)
                printf_s("\tL1 Context ID\n");
            if (bCMPXCHG16B)
                printf_s("\tCMPXCHG16B Instruction\n");
            if (bxTPRUpdateControl)
                printf_s("\txTPR Update Control\n");
            if (bPerfDebugCapabilityMSR)
                printf_s("\tPerf\\Debug Capability MSR\n");
            if (bSSE41Extensions)
                printf_s("\tSSE4.1 Extensions\n");
            if (bSSE42Extensions)
                printf_s("\tSSE4.2 Extensions\n");
            if (bPOPCNT)
                printf_s("\tPPOPCNT Instruction\n");

            i = 0;
            nIds = 1;
            while (i < (sizeof(szFeatures) / sizeof(const char *))) {
                if (nFeatureInfo & nIds) {
                    printf_s("\t");
                    printf_s(szFeatures[i]);
                    printf_s("\n");
                }

                nIds <<= 1;
                ++i;
            }
            if (bLAHF_SAHFAvailable)
                printf_s("\tLAHF/SAHF in 64-bit mode\n");
            if (bCmpLegacy)
                printf_s("\tCore multi-processing legacy mode\n");
            if (bSVM)
                printf_s("\tSecure Virtual Machine\n");
            if (bExtApicSpace)
                printf_s("\tExtended APIC Register Space\n");
            if (bAltMovCr8)
                printf_s("\tAltMovCr8\n");
            if (bLZCNT)
                printf_s("\tLZCNT instruction\n");
            if (bSSE4A)
                printf_s("\tSSE4A (EXTRQ, INSERTQ, MOVNTSD, MOVNTSS)\n");
            if (bMisalignedSSE)
                printf_s("\tMisaligned SSE mode\n");
            if (bPREFETCH)
                printf_s("\tPREFETCH and PREFETCHW Instructions\n");
            if (bSKINITandDEV)
                printf_s("\tSKINIT and DEV support\n");
            if (bSYSCALL_SYSRETAvailable)
                printf_s("\tSYSCALL/SYSRET in 64-bit mode\n");
            if (bExecuteDisableBitAvailable)
                printf_s("\tExecute Disable Bit\n");
            if (bMMXExtensions)
                printf_s("\tExtensions to MMX Instructions\n");
            if (bFFXSR)
                printf_s("\tFFXSR\n");
            if (b1GBSupport)
                printf_s("\t1GB page support\n");
            if (bRDTSCP)
                printf_s("\tRDTSCP instruction\n");
            if (b64Available)
                printf_s("\t64 bit Technology\n");
            if (b3DNowExt)
                printf_s("\t3Dnow Ext\n");
            if (b3DNow)
                printf_s("\t3Dnow! instructions\n");
            if (bNestedPaging)
                printf_s("\tNested Paging\n");
            if (bLBRVisualization)
                printf_s("\tLBR Visualization\n");
            if (bFP128)
                printf_s("\tFP128 optimization\n");
            if (bMOVOptimization)
                printf_s("\tMOVU Optimization\n");
        }
    }

    if (nExIds >= 0x80000004)
        printf_s("\nCPU Brand String: %s\n", CPUBrandString);

    if (nExIds >= 0x80000006) {
        printf_s("Cache Line Size = %d\n", nCacheLineSize);
        printf_s("L2 Associativity = %d\n", nL2Associativity);
        printf_s("Cache Size = %dK\n", nCacheSizeK);
    }

    for (i = 0;; i++) {
        __cpuidex(CPUInfo, 0x4, i);
        if (!(CPUInfo[0] & 0xf0)) break;

        if (i == 0) {
            nCores = CPUInfo[0] >> 26;
            printf_s("\n\nNumber of Cores = %d\n", nCores + 1);
        }

        nCacheType = (CPUInfo[0] & 0x1f);
        nCacheLevel = (CPUInfo[0] & 0xe0) >> 5;
        bSelfInit = (CPUInfo[0] & 0x100) >> 8;
        bFullyAssociative = (CPUInfo[0] & 0x200) >> 9;
        nMaxThread = (CPUInfo[0] & 0x03ffc000) >> 14;
        nSysLineSize = (CPUInfo[1] & 0x0fff);
        nPhysicalLinePartitions = (CPUInfo[1] & 0x03ff000) >> 12;
        nWaysAssociativity = (CPUInfo[1]) >> 22;
        nNumberSets = CPUInfo[2];

        printf_s("\n");

        printf_s("ECX Index %d\n", i);
        switch (nCacheType) {
        case 0:
            printf_s("   Type: Null\n");
            break;
        case 1:
            printf_s("   Type: Data Cache\n");
            break;
        case 2:
            printf_s("   Type: Instruction Cache\n");
            break;
        case 3:
            printf_s("   Type: Unified Cache\n");
            break;
        default:
            printf_s("   Type: Unknown\n");
        }

        printf_s("   Level = %d\n", nCacheLevel + 1);
        if (bSelfInit) {
            printf_s("   Self Initializing\n");
        } else {
            printf_s("   Not Self Initializing\n");
        }
        if (bFullyAssociative) {
            printf_s("   Is Fully Associatve\n");
        } else {
            printf_s("   Is Not Fully Associatve\n");
        }
        printf_s("   Max Threads = %d\n", nMaxThread + 1);
        printf_s("   System Line Size = %d\n", nSysLineSize + 1);
        printf_s("   Physical Line Partions = %d\n", nPhysicalLinePartitions + 1);
        printf_s("   Ways of Associativity = %d\n", nWaysAssociativity + 1);
        printf_s("   Number of Sets = %d\n", nNumberSets + 1);
    }

    return status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int GetsNumberOfValidExtendedIDs()
/*
功能：获取CPUID的最大功能号（基本的和扩展的）。

https://msdn.microsoft.com/en-us/library/hskdteyh(v=vs.100).aspx
*/
{
    int CPUInfo[4] = {-1};
    unsigned nIds, nExIds;

    __cpuid(CPUInfo, 0);
    nIds = CPUInfo[0];
    printf_s("%x\n", nIds);

    // Calling __cpuid with 0x80000000 as the InfoType argument gets the number of valid extended IDs.
    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    printf_s("%x\n", nExIds);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int GetCPUBrandString()
/*
功能：获取CPUID的最大功能号（基本的和扩展的）。

https://msdn.microsoft.com/en-us/library/hskdteyh(v=vs.100).aspx
*/
{
    int CPUInfo[4] = {-1};
    char CPUBrandString[0x40];
    unsigned nExIds;

    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    memset(CPUBrandString, 0, sizeof(CPUBrandString));

    if (nExIds < 4) {
        printf_s("No support CPU Brand String.\n");
    }

    //具体的原理为啥这样做，请看intel和amd的资料。
    for (unsigned i = 0x80000000; i <= nExIds; ++i) {
        __cpuid(CPUInfo, i);

        if (i == 0x80000002) {
            memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
        } else if (i == 0x80000003) {
            memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
        } else if (i == 0x80000004) {
            memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));
        } else {
            //啥也不做。
        }
    }

    if (nExIds >= 0x80000004) {//这个必定成立。
        //CPUBrandString的值为：        Intel(R) Core(TM) i3-3240 CPU @ 3.40GHz 注意前面有空格。
        printf_s("CPU Brand String: %s.\n", CPUBrandString);
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int GetCPUIdentificationString()
/*
获取CPU的厂商的代码

https://msdn.microsoft.com/en-us/library/hskdteyh(v=vs.100).aspx
*/
{
    char CPUString[0x20];
    int CPUInfo[4] = {-1};
    unsigned    nIds;

    // __cpuid with an InfoType argument of 0 returns the number of valid Ids in CPUInfo[0] and 
    // the CPU identification string in the other three array elements.
    // The CPU identification string is not in linear order. 
    // The code below arranges the information in a human readable form.
    __cpuid(CPUInfo, 0);
    nIds = CPUInfo[0];
    memset(CPUString, 0, sizeof(CPUString));
    *((int *)CPUString) = CPUInfo[1];
    *((int *)(CPUString + 4)) = CPUInfo[3];
    *((int *)(CPUString + 8)) = CPUInfo[2];

    printf_s("\n\nCPU String: %s\n", CPUString);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int is_support_pae()
/*
功能：检查是否开启：Physical address extensions。

参考：
https://msdn.microsoft.com/en-us/library/hskdteyh(v=vs.100).aspx
https://msdn.microsoft.com/en-us/library/h65k4tze(v=vs.100).aspx

另一个思路：检测cr4的第五位（从零开始）。
http://blogs.msdn.com/b/ntdebugging/archive/2010/06/22/part-3-understanding-pte-non-pae-and-x64.aspx

参考：
Intel? 64 and IA-32 Architectures Software Developer’s Manual Combined Volumes:1, 2A, 2B, 2C, 3A, 3B and 3C
的
Figure 3-8. Feature Information Returned in the EDX Register
和
Table 3-20. More on Feature Information Returned in the EDX Register
*/
{
    int CPUInfo[4] = {-1};
    int EDX;

    __cpuid(CPUInfo, 1);
    EDX = CPUInfo[3];
    if (_bittest((long *)&EDX, 6)) {
        printf_s("Physical address extensions.\n");
    } else {
        printf_s("NO Physical address extensions.\n");
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL is_support_vmx()
/*
功能：判断CPU是否支持VMX指令。
权威资料：23.6 DISCOVERING SUPPORT FOR VMX

System software can determine whether a processor supports VMX operation using CPUID.
If CPUID.1:ECX.VMX[bit 5] = 1, then VMX operation is supported.

made by correy
made at 2017.07.07
http://correy.webs.com
*/
{
    BOOL B = FALSE;
    int CPUInfo[4] = {-1};
    LONG ecx = 0;

    __cpuid(CPUInfo, 1);

    ecx = CPUInfo[2];

    B = _bittest(&ecx, 5);

    return B;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


BOOL is_support_intel()
{
    BOOL B = FALSE;
    char CPUString[0x20];
    int CPUInfo[4] = {-1};
    unsigned    nIds;

    // __cpuid with an InfoType argument of 0 returns the number of valid Ids in CPUInfo[0] and 
    // the CPU identification string in the other three array elements.
    // The CPU identification string is not in linear order. 
    // The code below arranges the information in a human readable form.
    __cpuid(CPUInfo, 0);
    nIds = CPUInfo[0];
    memset(CPUString, 0, sizeof(CPUString));
    *((int *)CPUString) = CPUInfo[1];
    *((int *)(CPUString + 4)) = CPUInfo[3];
    *((int *)(CPUString + 8)) = CPUInfo[2];

    //printf_s("\n\nCPU String: %s\n", CPUString);//GenuineIntel
    if (_stricmp(CPUString, "GenuineIntel") == 0) {
        B = TRUE;
    }

    return B;
}


BOOL is_support_cpuid()
/*
功能：检测CPU是否支持CPUID指令。

参考：
https://msdn.microsoft.com/en-us/library/aa983406(v=vs.100).aspx
https://msdn.microsoft.com/en-us/library/aa983392(v=vs.100).aspx

说明：
1.因为使用了size_t，所以支持32和64.
2.eflags就是WINDBG中的r efl命令显示的值。

intel手册的3.4.3.3 System Flags and IOPL Field节描述如下：
ID (bit 21)     Identification flag — The ability of a program to set or clear this flag indicates support for the CPUID instruction.

kd> .formats 0x200000
Evaluate expression:
  Hex:     00200000
  Decimal: 2097152
  Octal:   00010000000
  Binary:  00000000 00100000 00000000 00000000
  Chars:   . ..
  Time:    Sun Jan 25 14:32:32 1970
  Float:   low 2.93874e-039 high 0
  Double:  1.03613e-317
*/
{
    BOOL B = FALSE;
    SIZE_T eflags1;
    SIZE_T eflags2;

    eflags1 = __readeflags();
    __writeeflags(eflags1 | 0x200000);
    eflags2 = __readeflags();
    __writeeflags(eflags1);
    if (eflags1 == eflags2) {
        B = FALSE;
    } else {
        B = TRUE;
    }

    return B;
}


BOOL is_support_cpuid_ex()
/*
判断CPU是否支持CPUID指令。

The ID flag (bit 21) in the EFLAGS register indicates support for the CPUID instruction.
If a software procedure can set and clear this flag, the processor executing the procedure supports the CPUID instruction.
This instruction operates the same in non-64-bit modes and 64-bit mode.
*/
{
    BOOL B = FALSE;
    SIZE_T original;
    SIZE_T result;
    SIZE_T temp;

    original = __readeflags(); //读取
    //ASSERT(_bittest(&original, 21) == 0);//断言这个位为0.

    temp = original;
    _bittestandset((LONG *)&temp, 21);//设置这一位为1. 另一个办法是和0x200000进行或操作。

    __writeeflags(temp);//写入测试。

    result = __readeflags();//读取结果。

    __writeeflags(original);//恢复。

    //判断
    if (_bittest((const LONG *)&result, 21) == 0) {
        B = FALSE;
    } else {
        B = TRUE;
    }

    return B;
}


int is_support_ne()
{
    if (!is_support_cpuid()) {
        return 0;
    }

    if (!is_support_intel()) {
        return 0;
    }

    int CPUInfo[4] = {-1};
    unsigned    nExIds;
    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    if (nExIds < 1) {
        return 0;
    }

    __cpuid(CPUInfo, 0x80000001);
    LONG edx = CPUInfo[3];

    //即NX：No Execute。
    unsigned char b = _bittest(&edx, 20);
    if (b) {
        printf_s("Execute Disable Bit available.\n");
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int Intel64ArchitectureAvailable()
{
    if (!is_support_cpuid()) {
        return 0;
    }

    if (!is_support_intel()) {
        return 0;
    }

    int CPUInfo[4] = {-1};
    unsigned    nExIds;
    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    if (nExIds < 1) {
        return 0;
    }

    __cpuid(CPUInfo, 0x80000001);
    LONG edx = CPUInfo[3];

    //即NX：No Execute。
    unsigned char b = _bittest(&edx, 29);
    if (b) {
        printf_s("Intel 64 Architecture available if 1.\n");
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int is_support_msr()
/*
判断是否支持RDMSR and WRMSR指令
*/
{
    if (!is_support_cpuid()) {
        return 0;
    }

    if (!is_support_intel()) {
        return 0;
    }

    int CPUInfo[4] = {-1};
    unsigned    nIds;
    __cpuid(CPUInfo, 0);
    nIds = CPUInfo[0];
    if (nIds < 1) {
        return 0;
    }

    //Table 3-17. Information Returned by CPUID Instruction
    //Feature Information(see Figure 3 - 8 and Table 3 - 20)
    __cpuid(CPUInfo, 1);
    int edx = CPUInfo[3];

    unsigned char b = _bittest((const LONG *)&edx, 5);
    if (b) {
        printf_s("MSR–RDMSR and WRMSR Support.\n");
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int is_support_sysenter()
/*
检测是否支持SYSENTER and SYSEXIT and associated MSRs
*/
{
    if (!is_support_cpuid()) {
        return 0;
    }

    if (!is_support_intel()) {
        return 0;
    }

    int CPUInfo[4] = {-1};
    unsigned    nIds;
    __cpuid(CPUInfo, 0);
    nIds = CPUInfo[0];
    if (nIds < 1) {
        return 0;
    }

    //Table 3-17. Information Returned by CPUID Instruction
    //Feature Information(see Figure 3 - 8 and Table 3 - 20)
    __cpuid(CPUInfo, 1);
    int edx = CPUInfo[3];

    unsigned char b = _bittest((const LONG *)&edx, 11);
    if (b) {
        printf_s("The SYSENTER and SYSEXIT and associated MSRs are supported..\n");
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID IA32_VMX_PINBASED_CTLS()
/*
功能：获取IA32_VMX_PINBASED_CTLS寄存器的详细信息。

前置条件， CPUID.01H:ECX.[5] = 1 即判断CPU是否支持VMX指令的结果为真。
Capability Reporting Register of Pin-based VM-execution Controls (R/O)
See Appendix A.3.1, “Pin-Based VM-Execution Controls.”

made by correy
made at 2017.07.07
http://correy.webs.com
*/
{
    union IA32_VMX_PINBASED_CTLS ivpc;//在VS2012上，前面必须加个union。
    unsigned __int64 t = 0;

    t = __readmsr(0x481);

    ivpc.all = t;

    KdPrint(("allowed_0_settings:0x%x.\r\n", ivpc.fields.allowed_0_settings));
    KdPrint(("allowed_1_settings:0x%x.\r\n", ivpc.fields.allowed_1_settings));
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int GetMaxAddressBits()
/*
获取CPU支持的最大物理地址和线性地址的位数

注意：这个操作系统支持的是两个概念，操作系统的肯定小于这个。
*/
{
    if (!is_support_cpuid()) {
        return 0;
    }

    if (!is_support_intel()) {
        return 0;
    }

    int CPUInfo[4] = {-1};
    unsigned    nExIds;
    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    if (nExIds < 0x80000008) {
        return 0;
    }

    __cpuid(CPUInfo, 0x80000008);
    int eax = CPUInfo[0];

    /*
    Bits 07-00: #Physical Address Bits*
    Bits 15-8: #Linear Address Bits
    */
    int pab = eax & 0xff;
    int lab = eax & 0xff00;
    lab = lab / 0x100;

    printf_s("Physical Address Bits:%d.\n", pab);
    printf_s("Linear Address Bits:%d.\n", lab);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


int is_support_syscall()
{
    if (!is_support_cpuid()) {
        return 0;
    }

    if (!is_support_intel()) {
        return 0;
    }

    int CPUInfo[4] = {-1};
    unsigned    nExIds;
    __cpuid(CPUInfo, 0x80000000);
    nExIds = CPUInfo[0];
    if (nExIds < 1) {
        return 0;
    }

    __cpuid(CPUInfo, 0x80000001);
    int edx = CPUInfo[3];

    //如果在64位的系统上测试，编译为32的程序，这个获取是失败的，编译为64位程序，这个运行是成功的。
    //但是看说明，也是这样：SYSCALL/SYSRET available in 64-bit mode。
    unsigned char b = _bittest((const LONG *)&edx, 11);
    if (b) {
        printf_s("SYSCALL/SYSRET available in 64-bit mode.\n");
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID IA32_VMX_PROCBASED_CTLS()
/*
功能：获取IA32_VMX_PROCBASED_CTLS寄存器的详细信息。

前置条件， CPUID.01H:ECX.[5] = 1 即判断CPU是否支持VMX指令的结果为真。

Capability Reporting Register of Primary Processor-based VM-execution Controls (R/O)
See Appendix A.3.2, “Primary Processor-Based VM-Execution Controls.”

made by correy
made at 2017.07.07
http://correy.webs.com
*/
{
    union IA32_VMX_PROCBASED_CTLS ivpc;//在VS2012上，前面必须加个union。
    unsigned __int64 t = 0;

    t = __readmsr(0x482);

    ivpc.all = t;

    KdPrint(("allowed_0_settings:0x%x.\r\n", ivpc.fields.allowed_0_settings));
    KdPrint(("allowed_1_settings:0x%x.\r\n", ivpc.fields.allowed_1_settings));
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#ifdef _AMD64_
VOID IA32_VMX_PROCBASED_CTLS2()
/*
功能：获取IA32_VMX_PROCBASED_CTLS2寄存器的详细信息。

前置条件， If ( CPUID.01H:ECX.[5] && IA32_VMX_PROCBASED_CTLS[63]) 即判断CPU是否支持VMX指令的结果为真。

Capability Reporting Register of Secondary Processor-based VM-execution Controls (R/O)
See Appendix A.3.3, “Secondary Processor-Based VM-Execution Controls.”

made by correy
made at 2017.07.07
http://correy.webs.com
*/
{
    union IA32_VMX_PROCBASED_CTLS2 ivpc2;//在VS2012上，前面必须加个union。
    unsigned __int64 t = 0;

    t = __readmsr(0x482);
    if (_bittest64((LONG64 const *)&t, 63) == 0) {
        KdPrint(("NO support IA32_VMX_PROCBASED_CTLS2.\r\n"));
        return;
    }

    t = __readmsr(0x48B);

    ivpc2.all = t;

    KdPrint(("allowed_0_settings:0x%x.\r\n", ivpc2.fields.allowed_0_settings));
    KdPrint(("allowed_1_settings:0x%x.\r\n", ivpc2.fields.allowed_1_settings));
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS GetCpuTEMPERATURE()
/*
测试成功的获取Intel CPU温度的代码（真实机器）
此办法可以识别虚拟机，至少识别VMWARE等。

注意：测试环境最好不要用虚拟机，用真实的物理机器。
如是64位Windows，可以开启WINDBG的本机内核调试：
lkd> rdmsr 0x19C; rdmsr 0x1A2
msr[19c] = 00000000`88470000
msr[1a2] = 00000000`00691400
再计算。

注意：每个核心有个温度，不是每个CPU线程有个温度。

具体的做法有：
1.创建个设备，提供个借口供应用层用。
2.开启个定时器，在内核不停的打印消息。
*/

/*
CPUID.06H:EAX[bit0]

19CH 412   IA32_THERM_STATUS Core Thermal Monitor Status (R/W) See Table 35-2.

1A2H 418   MSR_TEMPERATURE_TARGET Package
15:0  Reserved.
23:16 Temperature Target (R)
The default thermal throttling or PROCHOT# activation temperature in degree C,
The effective temperature for thermal throttling or PROCHOT# activation is “Temperature Target” +“Target Offset”
29:24 Target Offset (R/W)
Specifies an offset in degrees C to adjust the throttling and 
PROCHOT# activation temperature from the default target specified in TEMPERATURE_TARGET (bits 23:16).
*/
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned __int64 tt = 0;
    unsigned __int64 ts = 0;
    int x = 0;
    int to = 0;
    int i = 0;
    int CPUInfo[4] = {-1};
    unsigned int t = 0;

    //识别是否支持CPUID指令。

    //识别是不是Intel处理器。

    //识别是否支持查询CPU的温度。
    __cpuid(CPUInfo, 6);
    t = CPUInfo[0];
    //CPUID.06H:EAX[bit0] == 1
    //可是下面的两个值获取的都为零。

    tt = __readmsr(MSR_TEMPERATURE_TARGET);//如果这个数字为0，可以认为是在虚拟机中，有的软件叫：耐热，可能是极限。
    ts = __readmsr(IA32_THERM_STATUS);

    //KdPrint(("MSR_TEMPERATURE_TARGET:0x%x.\r\n", tt));
    //KdPrint(("IA32_THERM_STATUS:0x%x.\r\n", ts));

    x = tt & (0xFF0000);//23:16 Temperature Target (R)
    to = ts & (0x7F0000);//22:16 Digital Readout (RO)

    i = x - to;
    i = i / 0x10000;

    KdPrint(("TEMPERATURE:%d.\r\n", i));
    //这个数字和别的软件有1-2度的差别。
    //不过Core-Temp和hwmonitor也是相差1-2度。

    return status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID READ_BASIC_VMX_INFORMATION()
/*
功能：获取BASIC_VMX_INFORMATION寄存器的详细信息。

前置条件， CPUID.01H:ECX.[5] = 1 即判断CPU是否支持VMX指令的结果为真。
See Appendix A.1, “Basic VMX Information.”

made by correy
made at 2017.07.07
http://correy.webs.com
*/
{
    union BASIC_VMX_INFORMATION bvi;//在VS2012上，前面必须加个union。
    unsigned __int64 t = 0;

    t = __readmsr(0x480);

    bvi.all = t;

    KdPrint(("vmcs_revision_identifier:0x%x.\r\n", bvi.fields.vmcs_revision_identifier));
    KdPrint(("region_size:0x%x.\r\n", bvi.fields.region_size));
    KdPrint(("supported_32:0x%x.\r\n", bvi.fields.supported_32));
    KdPrint(("supported_dual_moniter:0x%x.\r\n", bvi.fields.supported_dual_moniter));
    KdPrint(("memory_type:0x%x.\r\n", bvi.fields.memory_type));
    KdPrint(("vm_exit_report:0x%x.\r\n", bvi.fields.vm_exit_report));
    KdPrint(("vmx_capability_hint:0x%x.\r\n", bvi.fields.vmx_capability_hint));
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS GET_VMX_BASIC_INFO()
/*
功能：获取IA32_VMX_BASIC寄存器的信息。

注意：WINDBG命令：rdmsr 0x480

C 位域   https://msdn.microsoft.com/zh-cn/library/yszfawxh.aspx
C++ 位域 https://msdn.microsoft.com/zh-cn/library/ewwyfdbe.aspx

https://www.yumpu.com/en/document/view/53246903/david-weinstein-dweinstinsituseccom/27
*/
{
    NTSTATUS status = STATUS_SUCCESS;
    unsigned __int64 VMX_BASIC_MSR = 0;
    PMSR_IA32_VMX_BASIC vmx_basic;

    //1.识别是否支持CPUID指令。省略。

    //2.识别是不是Intel处理器。省略。

    //3.检测是否支持RDMSR/WRMSR指令。 省略。

    /*
    4.判断CPU是否支持虚拟化:CPUID.1:ECX.VMX[bit 5] = 1,因为：
    VMX capability MSRs are readonly; an attempt to write them (with WRMSR) produces a general-protection exception (#GP(0)).
    They do not exist on processors that do not support VMX operation; a
    n attempt to read them (with RDMSR) on such processors produces a general-protection exception (#GP(0))
    省略。
    */

    //5.读取并显示信息。

    VMX_BASIC_MSR = __readmsr(IA32_VMX_BASIC);//如果这个数字为0，可以认为是在虚拟机中，有的软件叫：耐热，可能是极限。

    vmx_basic = (PMSR_IA32_VMX_BASIC)&VMX_BASIC_MSR;

    KdPrint(("31-bit VMCS revision identifier:0x%x.\r\n", vmx_basic->VMCS_RID));
    KdPrint(("Bit 31 is always 0:0x%x.\r\n", vmx_basic->reserved1));
    KdPrint(("Bits 44:32 report the number of bytes:0x%x.\r\n", vmx_basic->number));
    KdPrint(("The values of bits 47:45 and bits 63:56 are reserved and are read as 0.:0x%x.\r\n", vmx_basic->reserved2));
    KdPrint(("Bit 48 indicates the width:0x%x. This bit is always 0 for processors that support Intel 64 architecture.\r\n", vmx_basic->width));
    KdPrint(("If bit 49 is read as 1, the logical processor supports the dual-monitor treatment of system-management interrupts and system - management mode.:0x%x.\r\n", vmx_basic->DMT_SMI_SMM));
    KdPrint(("Bits 53:50 report the memory type:0x%x.\r\n", vmx_basic->memory_type));
    KdPrint(("If bit 54 is read as 1:0x%x.\r\n", vmx_basic->INS_OUTS));
    KdPrint(("Bit 55 is read as 1 if any VMX controls that default to 1 may be cleared to 0. 同时还表示支持那几个（4个）：IA32_VMX_TRUE_XXX:0x%x.\r\n", vmx_basic->IA32_VMX_TRUE));
    KdPrint(("The values of bits 47:45 and bits 63:56 are reserved and are read as 0.:0x%x.\r\n", vmx_basic->reserved3));

    return status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


#ifdef _AMD64_
VOID IA32_VMX_EPT_VPID_CAP()
/*
功能：获取IA32_VMX_EPT_VPID_CAP寄存器的详细信息。

前置条件， If ( CPUID.01H:ECX.[5] && IA32_VMX_PROCBASED_CTLS[63] && ( IA32_VMX_PROCBASED_CTLS2[33] || IA32_VMX_PROCBASED_CTLS2[37]) )

Capability Reporting Register of EPT and VPID (R/O)
See Appendix A.10, “VPID and EPT Capabilities.”

made by correy
made at 2017.07.07
http://correy.webs.com
*/
{
    union IA32_VMX_EPT_VPID_CAP ivevc;//在VS2012上，前面必须加个union。
    unsigned __int64 t = 0;

    t = __readmsr(IA32_VMX_PROCBASED_CTLS_MSR);
    if (_bittest64((LONG64 const *)&t, 63) == 0) {
        return;
    }

    t = __readmsr(IA32_VMX_PROCBASED_CTLS2_MSR);
    if (_bittest64((LONG64 const *)&t, 33) || _bittest64((LONG64 const *)&t, 37)) {
        NOTHING;
    } else {
        return;
    }

    t = __readmsr(IA32_VMX_EPT_VPID_CAP_MSR);

    ivevc.all = t;

    KdPrint(("support_execute_only_pages:0x%x.\r\n", ivevc.fields.support_execute_only_pages));
    KdPrint(("support_page_walk_length4:0x%x.\r\n", ivevc.fields.support_page_walk_length4));//XXX
    KdPrint(("support_uncacheble_memory_type:0x%x.\r\n", ivevc.fields.support_uncacheble_memory_type));
    KdPrint(("support_write_back_memory_type:0x%x.\r\n", ivevc.fields.support_write_back_memory_type));//XXX
    KdPrint(("support_pde_2mb_pages:0x%x.\r\n", ivevc.fields.support_pde_2mb_pages));
    KdPrint(("support_pdpte_1_gb_pages:0x%x.\r\n", ivevc.fields.support_pdpte_1_gb_pages));
    KdPrint(("support_invept:0x%x.\r\n", ivevc.fields.support_invept));//XXX
    KdPrint(("support_accessed_and_dirty_flag:0x%x.\r\n", ivevc.fields.support_accessed_and_dirty_flag));
    KdPrint(("support_single_context_invept:0x%x.\r\n", ivevc.fields.support_single_context_invept));//XXX
    KdPrint(("support_all_context_invept:0x%x.\r\n", ivevc.fields.support_all_context_invept));//XXX
    KdPrint(("support_invvpid:0x%x.\r\n", ivevc.fields.support_invvpid));//XXX
    KdPrint(("support_individual_address_invvpid:0x%x.\r\n", ivevc.fields.support_individual_address_invvpid));//XXX
    KdPrint(("support_single_context_invvpid:0x%x.\r\n", ivevc.fields.support_single_context_invvpid));//XXX
    KdPrint(("support_all_context_invvpid:0x%x.\r\n", ivevc.fields.support_all_context_invvpid));//XXX
    KdPrint(("support_single_context_retaining_globals_invvpid:0x%x.\r\n", ivevc.fields.support_single_context_retaining_globals_invvpid));//XXX

    if (!ivevc.fields.support_page_walk_length4 ||
        !ivevc.fields.support_write_back_memory_type ||
        !ivevc.fields.support_invept ||
        !ivevc.fields.support_single_context_invept ||
        !ivevc.fields.support_all_context_invept ||
        !ivevc.fields.support_invvpid ||
        !ivevc.fields.support_individual_address_invvpid ||
        !ivevc.fields.support_single_context_invvpid ||
        !ivevc.fields.support_all_context_invvpid ||
        !ivevc.fields.support_single_context_retaining_globals_invvpid) {
        KdBreakPoint();
    }
}
#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


int EnumCpuCache()
/*
功能：枚举INTEL CPU 的各个层次的CACHE信息，如大小，类型等。
英文说法是:enumerate the deterministic cache parameters for each level of the cache hierarchy.

参考：WRK和INTEL等的资料。

made by correy
made at 2016.07.01
homepage:http://correy.webs.com
*/
{
    if (!is_support_cpuid()) {
        return 0;
    }

    if (!is_support_intel()) {
        return 0;
    }

    int CPUInfo[4] = {-1};
    unsigned    nExIds;
    __cpuid(CPUInfo, 0);
    nExIds = CPUInfo[0];
    if (nExIds < 4) {
        return 0;
    }

    //下面的算法参照WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\ke\amd64\initkr.c文件中的
    //KiSetCacheInformationIntel函数，当然还有INTEL的文档。
    INTEL_CACHE_INFO_EAX CacheInfoEax;
    INTEL_CACHE_INFO_EBX CacheInfoEbx;
    ULONG Index = 0;//Valid index values start from 0.
    ULONGLONG CacheSize;

    int nCores = 0;
    int nCacheType = 0;
    int nCacheLevel = 0;
    int nMaxThread = 0;
    int nSysLineSize = 0;
    int nPhysicalLinePartitions = 0;
    int nWaysAssociativity = 0;
    int nNumberSets = 0;
    int    bSelfInit = false;
    int    bFullyAssociative = false;

    for (;; Index += 1) {
        __cpuidex(CPUInfo, 4, Index); //注意：80000006H还有个信息。
        CacheInfoEax.Ulong = CPUInfo[0];
        CacheInfoEbx.Ulong = CPUInfo[1];

        if (CacheInfoEax.Type == IntelCacheNull) {
            break;//下面INTEL也说出了结束的标志。
        }

        //另一种退出方式是：https://msdn.microsoft.com/en-us/library/hskdteyh(v=vs.100).aspx 
        if (!(CPUInfo[0] & 0xf0))
            break;

        if (Index == 0) {
            nCores = CPUInfo[0] >> 26;
            printf_s("\n\nNumber of Cores = %d\n", nCores + 1);//感觉这个是错的。
        }

        nCacheType = (CPUInfo[0] & 0x1f);
        nCacheLevel = (CPUInfo[0] & 0xe0) >> 5;
        bSelfInit = (CPUInfo[0] & 0x100) >> 8;
        bFullyAssociative = (CPUInfo[0] & 0x200) >> 9;
        nMaxThread = (CPUInfo[0] & 0x03ffc000) >> 14;
        nSysLineSize = (CPUInfo[1] & 0x0fff);
        nPhysicalLinePartitions = (CPUInfo[1] & 0x03ff000) >> 12;
        nWaysAssociativity = (CPUInfo[1]) >> 22;
        nNumberSets = CPUInfo[2];

        printf_s("\n");
        printf_s("ECX Index %d\n", Index);
        switch (nCacheType) {
        case 0:
            printf_s("   Type: Null\n");
            break;
        case 1:
            printf_s("   Type: Data Cache\n");
            break;
        case 2:
            printf_s("   Type: Instruction Cache\n");
            break;
        case 3:
            printf_s("   Type: Unified Cache\n");
            break;
        default:
            printf_s("   Type: Unknown\n");
        }

        printf_s("   Level = %d\n", nCacheLevel + 1);//感觉无须加一。INTEL说了：starts at 1。估计微软的人还认为：starts at 0。
        if (bSelfInit) {
            printf_s("   Self Initializing\n");
        } else {
            printf_s("   Not Self Initializing\n");
        }

        if (bFullyAssociative) {
            printf_s("   Is Fully Associatve\n");
        } else {
            printf_s("   Is Not Fully Associatve\n");
        }

        printf_s("   Max Threads = %d\n", nMaxThread + 1);
        //printf_s("   System Line Size = %d\n", nSysLineSize + 1);
        //printf_s("   Physical Line Partions = %d\n", nPhysicalLinePartitions + 1);
        //printf_s("   Ways of Associativity = %d\n", nWaysAssociativity + 1);
        //printf_s("   Number of Sets = %d\n", nNumberSets + 1);

        //微软网站上的几个CPUID例子是没有计算CPU cache大小的，
        //如：https://msdn.microsoft.com/en-us/library/hskdteyh(v=vs.100).aspx ，这只是简单的列出值而已。 

        //WRK如是说：
        // Cache size = Ways x Partitions x LineSize x Sets. 
        // N.B. For fully-associative cache, the "Sets" returned from cpuid is actually the number of entries, not the "Ways".
        // Therefore the formula of evaluating the cache size below will still hold.

        /*
        INTEL如是说：

        INPUT EAX = 04H: Returns Deterministic Cache Parameters for Each Level

        When CPUID executes with EAX set to 04H and ECX contains an index value,
        the processor returns encoded data that describe a set of deterministic cache parameters (for the cache level associated with the input in ECX).
        Valid index values start from 0.

        Software can enumerate the deterministic cache parameters for each level of the cache hierarchy starting with an index value of 0,
        until the parameters report the value associated with the cache type field is 0.
        The architecturally defined fields reported by deterministic cache parameters are documented in Table 3-17.

        This Cache Size in Bytes
        = (Ways + 1) * (Partitions + 1) * (Line_Size + 1) * (Sets + 1)
        = (EBX[31:22] + 1) * (EBX[21:12] + 1) * (EBX[11:0] + 1) * (ECX + 1)

        The CPUID leaf 04H also reports data that can be used to derive the topology of processor cores in a physical package.
        This information is constant for all valid index values.
        Software can query the raw data reported by executing CPUID with EAX=04H and ECX=0 and 
        use it as part of the topology enumeration algorithm described in Chapter 8,
        “Multiple-Processor Management,” in the Intel? 64 and IA-32 Architectures Software Developer’s Manual, Volume 3A.
        */

        CacheSize = (CacheInfoEbx.Associativity + 1) * (CacheInfoEbx.Partitions + 1) * (CacheInfoEbx.LineSize + 1) * (CPUInfo[2] + 1);

        ULONGLONG Cache_Size = (nWaysAssociativity + 1) * (nPhysicalLinePartitions + 1) * (nSysLineSize + 1) * (nNumberSets + 1);
        //assert(Cache_Size == CacheSize);
        ASSERT(Cache_Size == CacheSize);
        /*
        其实：
        nWaysAssociativity可命名为Ways
        nPhysicalLinePartitions可命名为Partitions
        nSysLineSize可命名为Line_Size
        nNumberSets可命名为Sets
        */

        if (CacheSize >= (1024 * 1024)) {
            printf_s("   CacheSize = %dMB.\n", CacheSize / (1024 * 1024));
        } else {
            printf_s("   CacheSize = %dKB.\n", CacheSize / 1024);
        }
    }

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


VOID DisSmep()
/*
https://github.com/zerosum0x0/ShellcodeDriver/blob/master/shellcodedriver/shellcodedriver.c
SMEP机制是全局机制，不是限定某个进程的。
先检查是否开启SMEP，如果开启了就关闭。
*/
{
#ifdef _AMD64_

    unsigned __int64 cr4 = __readcr4();

    if (_bittest64((LONG64 const *)&cr4, 20)) {
        unsigned __int64 temp = cr4;
        InterlockedBitTestAndReset64((LONG64 volatile *)&temp, 20);//第20位设置为零。

        //unsigned __int64 temp = cr4 ^ (cr4 & (1 << 20));
        
        __writecr4(temp); // disable SMEP    
    } else {

    }

    //在驱动层执行用户态的代码（shellcode)了。

    //__writecr4(cr4);//恢复。
#else

    unsigned int cr4 = __readcr4();

    if (_bittest((LONG const *)&cr4, 20)) {
        unsigned int temp = cr4;
        InterlockedBitTestAndReset((LONG volatile *)&temp, 20);//第20位设置为零。

        //unsigned __int64 temp = cr4 ^ (cr4 & (1 << 20));

        __writecr4(temp); // disable SMEP    
    } else {

    }

    //在驱动层执行用户态的代码（shellcode)了。

    //__writecr4(cr4);//恢复。

#endif 
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
这里放置的是几个nt内核的几个虚拟化函数。

暂时这里只有HviIsAnyHypervisorPresent以及直接调用这个函数的三个函数。
HviGetHypervisorInterface
HviGetHypervisorVendorAndMaxFunction
HviIsHypervisorVendorMicrosoft
可以一次向上递归逆向，应该能逆向不少函数。
*/


bool IsAnyHypervisorPresent()
/*
char HviIsAnyHypervisorPresent()
{
  __int64 _RAX; // rax
  char b; // r8
  __int64 _RCX; // rcx
  __int64 _RAX; // rax
  __int64 _RAX; // rax

  _RAX = 1i64;
  b = 0;
  __asm { cpuid }
  if ( (int)_RCX < 0 )
  {
    b = 0;
    _RAX = 0x40000001i64;
    __asm { cpuid }
    if ( (_DWORD)_RAX != 'vnbX' )
      b = 1;
  }

  return b;
}
*/
{
    bool b = false;

    int CPUInfo[4] = {-1};
    __cpuid(CPUInfo, 0);
    if (CPUInfo[2] > 0) {
        __cpuid(CPUInfo, 0x40000001);
        if (CPUInfo[0] != 'vnbX') {
            b = true;
        }
    }

    return b;
}


bool GetHypervisorInterface(DWORD * cpuid)
/*
char __fastcall HviGetHypervisorInterface(_DWORD *a1)
{
  __int64 _RAX; // rax
  __int64 _RAX; // rax
  __int64 _RDX; // rdx
  __int64 _RCX; // rcx
  __int64 _RBX; // rbx

  LOBYTE(_RAX) = HviIsAnyHypervisorPresent();
  if ( (_BYTE)_RAX )
  {
    _RAX = 0x40000001i64;
    __asm { cpuid }
    *a1 = _RAX;
    a1[1] = _RBX;
    a1[2] = _RCX;
    a1[3] = _RDX;
  }
  else
  {
    *(_QWORD *)a1 = 0i64;
    *((_QWORD *)a1 + 1) = 0i64;
  }

  return _RAX;
}
*/
/*
这个函数的参数是：int CPUInfo[4]。
*/
{
    bool b = false;

    b = IsAnyHypervisorPresent();
    if (b) {
        int CPUInfo[4] = {-1};
        __cpuid(CPUInfo, 0x40000001);

        cpuid[0] = CPUInfo[0];
        cpuid[1] = CPUInfo[1];
        cpuid[2] = CPUInfo[2];
        cpuid[3] = CPUInfo[3];
    } else {
        cpuid[0] = 0;
        cpuid[1] = 0;
        cpuid[2] = 0;
        cpuid[3] = 0;
    }

    return b;
}


DWORD GetHypervisorVendorAndMaxFunction(DWORD * cpuid)
/*
char __fastcall HviGetHypervisorVendorAndMaxFunction(_DWORD *a1)
{
  LOBYTE(_RAX) = HviIsAnyHypervisorPresent();
  if ( (_BYTE)_RAX )
  {
    _RAX = 0x40000000i64;
    __asm { cpuid }
    *a1 = _RAX;
    a1[1] = _RBX;
    a1[2] = _RCX;
    a1[3] = _RDX;
  }
  else
  {
    *(_QWORD *)a1 = 0i64;
    *((_QWORD *)a1 + 1) = 0i64;
  }

  return _RAX;
}
*/
/*
这个函数的参数是：int CPUInfo[4]。
*/
{
    int CPUInfo[4] = {0};

    if (IsAnyHypervisorPresent()) {
        __cpuid(CPUInfo, 0x40000000);

        cpuid[0] = CPUInfo[0];
        cpuid[1] = CPUInfo[1];
        cpuid[2] = CPUInfo[2];
        cpuid[3] = CPUInfo[3];
    } else {
        cpuid[0] = 0;
        cpuid[1] = 0;
        cpuid[2] = 0;
        cpuid[3] = 0;
    }

    return cpuid[0];
}


bool IsHypervisorVendorMicrosoft()
/*
char HviIsHypervisorVendorMicrosoft()
{
  char b; // al
  __int64 _RAX; // rax
  __int64 _RDX; // rdx
  __int64 _RCX; // rcx
  __int64 _RBX; // rbx

  if ( !HviIsAnyHypervisorPresent() )
    goto error;

  _RAX = 0x40000000i64;
  __asm { cpuid }
  if ( (_DWORD)_RBX != 'rciM' )
    goto error;

  if ( (_DWORD)_RCX == 'foso' && (_DWORD)_RDX == 'vH t' )
    b = 1;
  else
error:
    b = 0;

  return b;
}
*/
/*
从这里细想可以拼出："Micrtosoft Hv".
*/
{
    bool ret = false;

    if (!IsAnyHypervisorPresent()) {
        return ret;
    }

    int CPUInfo[4] = {0};
    __cpuid(CPUInfo, 0x40000000);

    if (CPUInfo[1] != 'rciM') {
        return ret;
    }

    if (CPUInfo[2] == 'foso' && CPUInfo[3] == 'vH t') {
        ret = true;
    }

    return ret;
}


bool IsHypervisorMicrosoftCompatible()
/*
bool HviIsHypervisorMicrosoftCompatible()
{
  __int128 v1; // [rsp+20h] [rbp-28h] BYREF

  v1 = 0i64;
  HviGetHypervisorInterface(&v1);
  return (_DWORD)v1 == '1#vH';
}
*/
{
    DWORD CPUInfo[4] = {0};

    GetHypervisorInterface(&CPUInfo[0]);

    return CPUInfo[0] == '1#vH';
}


bool GetEnlightenmentInformation(DWORD * cpuid)
/*
char __fastcall HviGetEnlightenmentInformation(_DWORD *a1)
{
  __int64 _RAX; // rax
  __int64 _RAX; // rax
  __int64 _RDX; // rdx
  __int64 _RCX; // rcx
  __int64 _RBX; // rbx

  LOBYTE(_RAX) = HviIsHypervisorMicrosoftCompatible();
  if ( (_BYTE)_RAX )
  {
    _RAX = 0x40000004i64;
    __asm { cpuid }
    *a1 = _RAX;
    a1[1] = _RBX;
    a1[2] = _RCX;
    a1[3] = _RDX;
  }
  else
  {
    *(_QWORD *)a1 = 0i64;
    *((_QWORD *)a1 + 1) = 0i64;
  }

  return _RAX;
}
*/
{
    bool b = false;

    b = IsHypervisorMicrosoftCompatible();
    if (b) {
        int CPUInfo[4] = {-1};
        __cpuid(CPUInfo, 0x40000004);

        cpuid[0] = CPUInfo[0];
        cpuid[1] = CPUInfo[1];
        cpuid[2] = CPUInfo[2];
        cpuid[3] = CPUInfo[3];
    } else {
        cpuid[0] = 0;
        cpuid[1] = 0;
        cpuid[2] = 0;
        cpuid[3] = 0;
    }

    return b;
}


bool GetHypervisorFeatures(DWORD * cpuid)
/*
char __fastcall HviGetHypervisorFeatures(_DWORD *a1)
{
  __int64 _RAX; // rax
  __int64 _RAX; // rax
  __int64 _RDX; // rdx
  __int64 _RCX; // rcx
  __int64 _RBX; // rbx

  LOBYTE(_RAX) = HviIsHypervisorMicrosoftCompatible();
  if ( (_BYTE)_RAX )
  {
    _RAX = 0x40000003i64;
    __asm { cpuid }
    *a1 = _RAX;
    a1[1] = _RBX;
    a1[2] = _RCX;
    a1[3] = _RDX;
  }
  else
  {
    *(_QWORD *)a1 = 0i64;
    *((_QWORD *)a1 + 1) = 0i64;
  }

  return _RAX;
}
*/
{
    bool b = false;

    b = IsHypervisorMicrosoftCompatible();
    if (b) {
        int CPUInfo[4] = {-1};
        __cpuid(CPUInfo, 0x40000003);

        cpuid[0] = CPUInfo[0];
        cpuid[1] = CPUInfo[1];
        cpuid[2] = CPUInfo[2];
        cpuid[3] = CPUInfo[3];
    } else {
        cpuid[0] = 0;
        cpuid[1] = 0;
        cpuid[2] = 0;
        cpuid[3] = 0;
    }

    return b;
}


bool GetHypervisorVersion(DWORD * cpuid)
/*
char __fastcall HviGetHypervisorVersion(_DWORD *a1)
{
  __int64 _RAX; // rax
  __int64 _RAX; // rax
  __int64 _RDX; // rdx
  __int64 _RCX; // rcx
  __int64 _RBX; // rbx

  LOBYTE(_RAX) = HviIsHypervisorMicrosoftCompatible();
  if ( (_BYTE)_RAX )
  {
    _RAX = 0x40000002i64;
    __asm { cpuid }
    *a1 = _RAX;
    a1[1] = _RBX;
    a1[2] = _RCX;
    a1[3] = _RDX;
  }
  else
  {
    *(_QWORD *)a1 = 0i64;
    *((_QWORD *)a1 + 1) = 0i64;
  }

  return _RAX;
}
*/
{
    bool b = false;

    b = IsHypervisorMicrosoftCompatible();
    if (b) {
        int CPUInfo[4] = {-1};
        __cpuid(CPUInfo, 0x40000002);

        cpuid[0] = CPUInfo[0];
        cpuid[1] = CPUInfo[1];
        cpuid[2] = CPUInfo[2];
        cpuid[3] = CPUInfo[3];
    } else {
        cpuid[0] = 0;
        cpuid[1] = 0;
        cpuid[2] = 0;
        cpuid[3] = 0;
    }

    return b;
}


bool GetImplementationLimits(DWORD * cpuid)
/*
char __fastcall HviGetImplementationLimits(_DWORD *a1)
{
  __int64 _RAX; // rax
  __int64 _RAX; // rax
  __int64 _RDX; // rdx
  __int64 _RCX; // rcx
  __int64 _RBX; // rbx

  LOBYTE(_RAX) = HviIsHypervisorMicrosoftCompatible();
  if ( (_BYTE)_RAX )
  {
    _RAX = 0x40000005i64;
    __asm { cpuid }
    *a1 = _RAX;
    a1[1] = _RBX;
    a1[2] = _RCX;
    a1[3] = _RDX;
  }
  else
  {
    *(_QWORD *)a1 = 0i64;
    *((_QWORD *)a1 + 1) = 0i64;
  }

  return _RAX;
}
*/
{
    bool b = false;

    b = IsHypervisorMicrosoftCompatible();
    if (b) {
        int CPUInfo[4] = {-1};
        __cpuid(CPUInfo, 0x40000005);

        cpuid[0] = CPUInfo[0];
        cpuid[1] = CPUInfo[1];
        cpuid[2] = CPUInfo[2];
        cpuid[3] = CPUInfo[3];
    } else {
        cpuid[0] = 0;
        cpuid[1] = 0;
        cpuid[2] = 0;
        cpuid[3] = 0;
    }

    return b;
}


int HviTest()
/*
注意：这里的测试代码是在应用层测试的。
*/
{
    bool b = IsAnyHypervisorPresent();

    DWORD HypervisorInterface[4] = {0};
    b = GetHypervisorInterface(&HypervisorInterface[0]);

    DWORD HypervisorVendor[4] = {0};
    DWORD MaxFunction = GetHypervisorVendorAndMaxFunction(&HypervisorVendor[0]);
    MaxFunction = 0;

    b = IsHypervisorVendorMicrosoft();

    b = IsHypervisorMicrosoftCompatible();

    DWORD EnlightenmentInformation[4] = {0};
    b = GetEnlightenmentInformation(&EnlightenmentInformation[0]);

    DWORD HypervisorFeatures[4] = {0};
    b = GetHypervisorFeatures(&HypervisorFeatures[0]);

    DWORD HypervisorVersion[4] = {0};
    b = GetHypervisorVersion(&HypervisorVersion[0]);

    DWORD ImplementationLimits[4] = {0};
    b = GetImplementationLimits(&ImplementationLimits[0]);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////
