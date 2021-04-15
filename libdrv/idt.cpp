#include "idt.h"


#pragma warning(disable:6066)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////


#if defined(_WIN64)
void show_idt(int i)
/*
i��ȡֵ������0.
*/
{
    AMD64_DESCRIPTOR idtr = {0};

    SIZE_T r = 0;
    PVOID p = 0;
    int index = 0;
    int maximun = 0;

    PKIDTENTRY64 pkidte = 0;
    SIZE_T ISR = 0;

    KeSetSystemAffinityThread(i + 1);
    __sidt(&idtr);//KeGetPcr�������ǿ��õ�Ӵ��
    KeRevertToUserAffinityThread();

    p = &idtr.Pad[1];
    r = *(SIZE_T *)p;

    pkidte = (PKIDTENTRY64)r;

    if (idtr.Pad[0] % sizeof(KIDTENTRY64) == 0) {//idtr.Pad[0] == 0xfff.
        maximun = idtr.Pad[0] / sizeof(KIDTENTRY64);
    } else {
        maximun = idtr.Pad[0] / sizeof(KIDTENTRY64);
        maximun++;//�����Ҳ��256.
    }

    for (; index < maximun; index++) {
        PKIDTENTRY64 pkidte_t = &pkidte[index];

        ISR = pkidte_t->OffsetHigh;
        ISR = (ISR << 32);
        ISR += (pkidte_t->OffsetLow + (pkidte_t->OffsetMiddle << 16));

        if (pkidte_t->IstIndex == 0) {
            KdPrint(("��%d��CPU�ĵ�0x%02x�жϵĵ�ַ:0x%p\n", i, index, ISR));
        } else {
            KdPrint(("��%d��CPU�ĵ�0x%02x�жϵĵ�ַ:0x%p\n", i, index, ISR));//�����Խ�һ����ȡStack����Ϣ��
        }
    }
}
#else 
void show_idt(int i)
/*
i��ȡֵ������0.
*/
{
    //SIZE_T IDTR;
    X86_DESCRIPTOR idtr = {0};//A pointer to the memory location where the IDTR is stored.

    SIZE_T r = 0;
    PVOID p = 0;
    int index = 0;
    int maximun = 0;

    PKIDTENTRY pkidte;
    SIZE_T ISR = 0;

    KeSetSystemAffinityThread(i + 1);
    __sidt(&idtr);// http://msdn.microsoft.com/zh-cn/library/aa983358%28v=vs.120%29.aspx ��һ��˼·���Լ�ʵ�֣�KeGetPcr()��
    KeRevertToUserAffinityThread();

    p = &idtr.Limit;
    r = *(SIZE_T *)p;

    pkidte = (PKIDTENTRY)r;

    /*
    ��ʵֱ�ӣ�
    maximun = (idtr.Base + 1) / sizeof(KIDTENTRY);
    Ҳ���ԡ�
    maximunһ�����256.
    */
    if (idtr.Pad % sizeof(KIDTENTRY) == 0) {
        maximun = idtr.Pad / sizeof(KIDTENTRY);
    } else {
        maximun = idtr.Pad / sizeof(KIDTENTRY);
        maximun++;
    }

    for (; index < maximun; index++) //��һ��˼·�Ǹ���Limit�������������һ����2047 == 0x7ff.
    {
        PKIDTENTRY pkidte_t = &pkidte[index];

        if (pkidte_t->ExtendedOffset) {
            ISR = pkidte_t->Offset + (pkidte_t->ExtendedOffset << 16);
            KdPrint(("��%d��CPU�ĵ�0x%02x�жϵĵ�ַ:0x%p\n", i, index, ISR));
        } else {//ע�⣺pkidte_t->ExtendedOffset == 0������ķ�����
            if (pkidte_t->Selector == 8) {
                KdPrint(("��%d��CPU�ĵ�0x%02x�ж�û��ʹ�á�Offset:0x%x,Access:0x%x.\n", i, index, pkidte_t->Offset, pkidte_t->Access));
            } else {
                KdPrint(("��%d��CPU�ĵ�0x%02x�жϵ�Task Selector:0x%x, Offset:0x%x, Access:0x%x��\n", i, index, pkidte_t->Selector, pkidte_t->Offset, pkidte_t->Access));
            }
        }
    }
}
#endif


NTSTATUS TestIdt()
{
    int i = 0;

    for (; i < KeNumberProcessors; i++)//KeQueryMaximumProcessorCount()
    {
        show_idt(i);
    }

    return STATUS_SUCCESS;
}
