#include "idt.h"


#pragma warning(disable:6066)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////


#if defined(_WIN64)
void show_idt(int i)
/*
i的取值可以是0.
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
    __sidt(&idtr);//KeGetPcr函数可是可用的哟！
    KeRevertToUserAffinityThread();

    p = &idtr.Pad[1];
    r = *(SIZE_T *)p;

    pkidte = (PKIDTENTRY64)r;

    if (idtr.Pad[0] % sizeof(KIDTENTRY64) == 0) {//idtr.Pad[0] == 0xfff.
        maximun = idtr.Pad[0] / sizeof(KIDTENTRY64);
    } else {
        maximun = idtr.Pad[0] / sizeof(KIDTENTRY64);
        maximun++;//这个数也是256.
    }

    for (; index < maximun; index++) {
        PKIDTENTRY64 pkidte_t = &pkidte[index];

        ISR = pkidte_t->OffsetHigh;
        ISR = (ISR << 32);
        ISR += (pkidte_t->OffsetLow + (pkidte_t->OffsetMiddle << 16));

        if (pkidte_t->IstIndex == 0) {
            KdPrint(("第%d号CPU的第0x%02x中断的地址:0x%p\n", i, index, ISR));
        } else {
            KdPrint(("第%d号CPU的第0x%02x中断的地址:0x%p\n", i, index, ISR));//还可以进一步获取Stack的信息。
        }
    }
}
#else 
void show_idt(int i)
/*
i的取值可以是0.
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
    __sidt(&idtr);// http://msdn.microsoft.com/zh-cn/library/aa983358%28v=vs.120%29.aspx 另一个思路是自己实现：KeGetPcr()。
    KeRevertToUserAffinityThread();

    p = &idtr.Limit;
    r = *(SIZE_T *)p;

    pkidte = (PKIDTENTRY)r;

    /*
    其实直接：
    maximun = (idtr.Base + 1) / sizeof(KIDTENTRY);
    也可以。
    maximun一般等于256.
    */
    if (idtr.Pad % sizeof(KIDTENTRY) == 0) {
        maximun = idtr.Pad / sizeof(KIDTENTRY);
    } else {
        maximun = idtr.Pad / sizeof(KIDTENTRY);
        maximun++;
    }

    for (; index < maximun; index++) //另一个思路是根据Limit来遍历，这个数一般是2047 == 0x7ff.
    {
        PKIDTENTRY pkidte_t = &pkidte[index];

        if (pkidte_t->ExtendedOffset) {
            ISR = pkidte_t->Offset + (pkidte_t->ExtendedOffset << 16);
            KdPrint(("第%d号CPU的第0x%02x中断的地址:0x%p\n", i, index, ISR));
        } else {//注意：pkidte_t->ExtendedOffset == 0的情况的分析。
            if (pkidte_t->Selector == 8) {
                KdPrint(("第%d号CPU的第0x%02x中断没有使用。Offset:0x%x,Access:0x%x.\n", i, index, pkidte_t->Offset, pkidte_t->Access));
            } else {
                KdPrint(("第%d号CPU的第0x%02x中断的Task Selector:0x%x, Offset:0x%x, Access:0x%x。\n", i, index, pkidte_t->Selector, pkidte_t->Offset, pkidte_t->Access));
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
