#include "pcr.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//这是X64的定义。
//这里用代码实现，这个函数肯定没有导出。
//__forceinline
//PKPCR
//KeGetPcr (
//    VOID
//    )
//
//{
//    return (PKPCR)(ULONG_PTR)KIPCR();
//}


//这是X64的定义。
//__forceinline
//PKPCR
//KeGetPcr (
//    VOID
//    )
//
//{
//    return (PKPCR)__readgsqword(FIELD_OFFSET(KPCR, Self));
//}


/*
仿照系统的写的64位的KeGetPcr，
自己写一个X86的。
*/
#ifdef _X86_
__forceinline
PKPCR
KeGetPcr(
    VOID
)
{
    return (PKPCR)__readfsdword(FIELD_OFFSET(KPCR, SelfPcr));
}
#endif
//另一种思路是：直接汇编。
//__asm {  
//    movzx eax, _PCR
//        mov pkpcr,eax
//}
//注意：这一行.
//#define _PCR   fs:[0]  


struct _KPRCB * KeGetPrcb(PKPCR pkpcr)
    /*
    _KPRCB结构没有公开。
    WRK和WINDBG肯定有。
    而且有32和64之分。
    wrk\WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\inc\i386.h
    wrk\WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\inc\amd64.h
    */
{
#ifdef _X86_
    return pkpcr->Prcb;
#endif

#if !defined(MIDL_PASS) && defined(_M_AMD64)
    return pkpcr->CurrentPrcb;
#endif
}


NTSTATUS GetPcrTest()
{
    NTSTATUS Status = STATUS_SUCCESS;
    PKPCR pkpcr;
    struct _KPRCB * Prcb;
    //DBGKD_GET_VERSION64 * pdgv;
    //PKDDEBUGGER_DATA64 pkdd;
    //char * p;

    KeSetSystemAffinityThread(1);
    pkpcr = KeGetPcr();
    KeRevertToUserAffinityThread();

    Prcb = KeGetPrcb(pkpcr);

    ////下面打印获取一些没有导出的重要的信息，如诸多变量。
    //pdgv = pkpcr->KdVersionBlock;//在X64下这个等于零。

    ////pkdd = (PKDDEBUGGER_DATA64)((char *)pkpcr + sizeof(DBGKD_GET_VERSION64));
    //p = (char *)pdgv;
    //p += sizeof(DBGKD_GET_VERSION64);
    //pkdd = (PKDDEBUGGER_DATA64)p;     

    return Status;
}
