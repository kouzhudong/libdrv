#include "pcr.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


//����X64�Ķ��塣
//�����ô���ʵ�֣���������϶�û�е�����
//__forceinline
//PKPCR
//KeGetPcr (
//    VOID
//    )
//
//{
//    return (PKPCR)(ULONG_PTR)KIPCR();
//}


//����X64�Ķ��塣
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
����ϵͳ��д��64λ��KeGetPcr��
�Լ�дһ��X86�ġ�
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
//��һ��˼·�ǣ�ֱ�ӻ�ࡣ
//__asm {  
//    movzx eax, _PCR
//        mov pkpcr,eax
//}
//ע�⣺��һ��.
//#define _PCR   fs:[0]  


struct _KPRCB * KeGetPrcb(PKPCR pkpcr)
    /*
    _KPRCB�ṹû�й�����
    WRK��WINDBG�϶��С�
    ������32��64֮�֡�
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

    ////�����ӡ��ȡһЩû�е�������Ҫ����Ϣ������������
    //pdgv = pkpcr->KdVersionBlock;//��X64����������㡣

    ////pkdd = (PKDDEBUGGER_DATA64)((char *)pkpcr + sizeof(DBGKD_GET_VERSION64));
    //p = (char *)pdgv;
    //p += sizeof(DBGKD_GET_VERSION64);
    //pkdd = (PKDDEBUGGER_DATA64)p;     

    return Status;
}
