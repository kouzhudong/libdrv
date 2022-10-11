#include "gdt.h"
#include "pcr.h"


#pragma warning(disable:6066)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
���ݣ�Table 3-1. Code- and Data-Segment Types������WINDBG��dg����塣
*/
char SegmentTypes[][256] = {
    "<Reserved>",//Data Read-Only��д�ǣ�Data RO��Ҳ����Ϊ�ǣ� <Reserved>������ṹ��UINT64��ȫ��Ϊ�㣬Ҳ����Ϊ��Reserved��
    "Data RO AC",//Data Read-Only, accessed
    "Data RW",//Data Read/Write
    "Data RW AC",//Data Read/Write, accessed
    "Data RO ED",//Data Read-Only, expand-down
    "Data RO ED AC",//Data Read-Only, expand-down, accessed
    "Data RW ED",//Data Read/Write, expand-down
    "Data RW ED AC",//Data Read/Write, expand-down, accessed

    "Code EO",//Code Execute-Only
    "Code EO AC",//Code Execute-Only, accessed
    "Code RE",//Code Execute/Read �ӿո��Ա���ʾ�Ķ��롣
    "Code RE AC",//Code Execute/Read, accessed
    "Code EO CO",//Code Execute-Only, conforming
    "Code EO CO AC",//Code Execute-Only, conforming, accessed
    "Code RE CO",//Code Execute/Read, conforming
    "Code RE CO AC",//Code Execute/Read, conforming, accessed
    "TSS32 Busy ",//���Ҳ����ʾֻҪʶ����TSS�����ݡ�
    "TSS32 Avl" //�����X86�ϳ����ˡ�
};


//#ifdef _X86_
////__forceinline 
//PKPCR KeGetPcr(VOID)
//{
//    return (PKPCR)__readfsdword(FIELD_OFFSET(KPCR, SelfPcr));
//}
//#endif


USHORT NTAPI GetGdtLimit();//��ຯ����


#if defined(_WIN64)
void show_gdt(int i)
/*
i��ȡֵ������0.
*/
{
    //SIZE_T IDTR;
    //X86_DESCRIPTOR gdtr = {0};//A pointer to the memory location where the IDTR is stored.
    //KGDTENTRY * GDT = 0;
    USHORT GdtLimit = 0;

    //SIZE_T r = 0;
    //PVOID p = 0;
    int index = 0;
    int maximun = 0;

    PKGDTENTRY64 pkgdte;
    //SIZE_T ISR = 0;

    KeSetSystemAffinityThread(i + 1);
    pkgdte = KeGetPcr()->GdtBase;//û��__sgdt,Ҳ����sgdt���ָ��İ취�����������ȡ��û�г��ȡ�
    GdtLimit = GetGdtLimit();//һ�����0x7f.
    KeRevertToUserAffinityThread();

    //p = &gdtr.Limit;
    //r = * (SIZE_T *)p;
    //pkgdte = (PKGDTENTRY)r; 

    /*
    ��ʵֱ�ӣ�
    maximun = (idtr.Base + 1) / sizeof(KIDTENTRY);
    Ҳ���ԡ�
    maximunһ�����256.
    */
    //if (gdtr.Pad % sizeof(KIDTENTRY) == 0) {
    //    maximun = gdtr.Pad / sizeof(KIDTENTRY);
    //} else {
    //    maximun = gdtr.Pad / sizeof(KIDTENTRY);
    //    maximun++;
    //}

    //if (GdtLimit % sizeof(KGDTENTRY64) == 0) {
    //    maximun = GdtLimit / sizeof(KGDTENTRY64);
    //} else {
    //    maximun = GdtLimit / sizeof(KGDTENTRY64);
    //    maximun++;//һ����128.
    //}

    maximun = (GdtLimit + 1) / sizeof(KGDTENTRY64);

    /*
    ��ʾ��ʽ��
    CPU SN Sel        Base              Limit          Type    Pl Size Gran Pres Long Flags
    --- -- ---- ----------------- ----------------- ---------- -- ---- ---- ---- ---- --------

    ע�ͣ�CPU��SN���Լ���ӵġ�SN��Segment Name,�磺CS��DS��FS��.
    */
    KdPrint(("Sel        Base             Limit             Type   DPl Size Gran Pres Long Flags\n"));//CPU SN 
    KdPrint(("---- ---------------- ---------------- ------------- --- ---- ---- ---- ---- --------\n"));//--- -- 
    KdPrint(("\n"));

    for (; index < maximun; index++) {
        PKGDTENTRY64 pkgdte_t = &pkgdte[index];
        SIZE_T Base = 0;
        SIZE_T Limit = 0;
        ULONG  Type = 0;
        char * size = NULL;
        char * Granularity = NULL;
        char * Present = NULL;
        char * LongMode = NULL;
        int    Flags = 0;

        Base = pkgdte_t->Bits.BaseHigh;
        Base = (Base << 24);
        Base += (pkgdte_t->BaseLow + (pkgdte_t->Bits.BaseMiddle << 16));

        Limit = pkgdte_t->LimitLow + (pkgdte_t->Bits.LimitHigh << 16);

        if (pkgdte_t->Bits.DefaultBig && Base) {
            //�����λΪ1.��F.
            Base += 0xffffffff00000000;
        }

        if (pkgdte_t->Bits.DefaultBig && pkgdte_t->Bits.Granularity) {
            //�����λΪ1.��F.
            //SIZE_T t = Limit;
            Limit = (Limit << 12);
            Limit += PAGE_SIZE - 1;
        }

        Type = pkgdte_t->Bits.Type;
        _bittestandreset((LONG *)&Type, 4);//��Ϊ���������Sλ������Ҫ������λ��־��

        if (pkgdte_t->Bits.DefaultBig) {
            size = "Bg  ";//Big �ӿո���Ϊ�˶�����ʾ��
        } else {
            size = "Nb  ";//Not Big �ӿո���Ϊ�˶�����ʾ��
        }

        if (pkgdte_t->Bits.Granularity) {
            Granularity = "Pg  ";//Page �ӿո���Ϊ�˶�����ʾ��
        } else {
            Granularity = "By  ";//Byte �ӿո���Ϊ�˶�����ʾ��
        }

        if (pkgdte_t->Bits.Present) {
            Present = "P   ";//Present �ӿո���Ϊ�˶�����ʾ��
        } else {
            Present = "NP  ";//NO Present �ӿո���Ϊ�˶�����ʾ��
        }

        if (pkgdte_t->Bits.LongMode) {
            LongMode = "Lo  ";//Long �ӿո���Ϊ�˶�����ʾ��
        } else {
            LongMode = "Nl  ";//NO long �ӿո���Ϊ�˶�����ʾ��
        }

        Flags = (pkgdte_t->Bytes.Flags2 >> 4);//ȥ��Segment limit���Ǽ�λ��
        Flags = Flags << 8;
        Flags = Flags + pkgdte_t->Bytes.Flags1;

        KdPrint(("%04x %p %p %13s %03x %s %s %s %s 0x%04x\n",
                 index * 8, //sizeof (KGDTENTRY)
                 Base,
                 Limit,
                 SegmentTypes[Type],
                 pkgdte_t->Bits.Dpl,
                 size,
                 Granularity,
                 Present,
                 LongMode,
                 Flags
                 ));

        //if (pkgdte_t->Bits.Present)
        //{
        //    KdPrint(("��%d��CPU��GDT��Sel:0x%03x, Base:0x%016p, Limit:0x%016p, type:0x%02x, Dpl:0x%x, Pres:0x%x, Sys:0x%x, LongMode:0x%x, Default_Big:0x%x, Granularity:0x%x.\n", 
        //        i, index * sizeof (KGDTENTRY64), Base, Limit,
        //        pkgdte_t->Bits.Type,
        //        pkgdte_t->Bits.Dpl,
        //        pkgdte_t->Bits.Present,//�ٴ�ӡһ�ΰɣ�
        //        pkgdte_t->Bits.System,
        //        pkgdte_t->Bits.LongMode,
        //        pkgdte_t->Bits.DefaultBig,
        //        pkgdte_t->Bits.Granularity
        //        ));
        //}
        //else //<Reserved> 
        //{
        //    KdPrint(("��%d��CPU��GDT��Sel:0x%03x is Reserved!\n", i, index * sizeof (KGDTENTRY64)));
        //}


        ////ż��������һ�����ԣ���0x38��ֵ���ԣ�
        //Base = pkgdte_t->BaseLow + (pkgdte_t->HighWord.Bits.BaseHi << 24) + (pkgdte_t->HighWord.Bits.BaseMid << 16);//��ʵ��λ����� | ��

        //if (pkgdte_t->HighWord.Bits.Granularity && BooleanFlagOn(pkgdte_t->HighWord.Bits.Type, 2 ) ) {//���ڱ�־λ���㷨����Ȩ�����ϡ�
        //    Limit = pkgdte_t->LimitLow + (pkgdte_t->HighWord.Bits.LimitHi << 16);
        //    Limit *= PAGE_SIZE;
        //    Limit += PAGE_SIZE - 1;
        //} else {
        //    Limit = pkgdte_t->LimitLow + (pkgdte_t->HighWord.Bits.LimitHi << 16);
        //}

        //KdPrint(("��%d��CPU��GDT��Sel:0x%03x, Base:0x%08x, Limit:0x%08x, type:0x%02x, Dpl:0x%x, Pres:0x%x, Sys:0x%x,Default_Big:0x%x, Granularity:0x%x.\n", 
        //    i, index * sizeof (KGDTENTRY), Base, Limit,
        //    pkgdte_t->HighWord.Bits.Type,
        //    pkgdte_t->HighWord.Bits.Dpl,
        //    pkgdte_t->HighWord.Bits.Pres,
        //    pkgdte_t->HighWord.Bits.Sys,
        //    pkgdte_t->HighWord.Bits.Default_Big,
        //    pkgdte_t->HighWord.Bits.Granularity
        //    ));

        /*
        �����Default_Big��Ӧdg�����size.
        �����Sys��Ӧdg�����long.
        Flags��ֵ���ڱ����ӡ�ˣ�����Ͳ��ٴ�ӡ�ˡ�
        */
    }
}
#else 
void show_gdt(int i)
/*
i��ȡֵ������0.
*/
{
    //SIZE_T IDTR;
    //X86_DESCRIPTOR gdtr = {0};//A pointer to the memory location where the IDTR is stored.
    //KGDTENTRY * GDT = 0;
    USHORT GdtLimit = 0;

    //SIZE_T r = 0;
    //PVOID p = 0;
    int index = 0;
    int maximun = 0;

    PKGDTENTRY pkgdte;
    //SIZE_T ISR = 0;

    KeSetSystemAffinityThread(i + 1);
    pkgdte = KeGetPcr()->GDT;//û��__sgdt,Ҳ����sgdt���ָ��İ취�����������ȡ��û�г��ȡ�
    GdtLimit = GetGdtLimit();//һ�����0x3ff.
    KeRevertToUserAffinityThread();

    //p = &gdtr.Limit;
    //r = * (SIZE_T *)p;
    //pkgdte = (PKGDTENTRY)r; 

    /*
    ��ʵֱ�ӣ�
    maximun = (idtr.Base + 1) / sizeof(KIDTENTRY);
    Ҳ���ԡ�
    maximunһ�����256.
    */
    //if (gdtr.Pad % sizeof(KIDTENTRY) == 0) {
    //    maximun = gdtr.Pad / sizeof(KIDTENTRY);
    //} else {
    //    maximun = gdtr.Pad / sizeof(KIDTENTRY);
    //    maximun++;
    //}

    if (GdtLimit % sizeof(KGDTENTRY) == 0) {
        maximun = GdtLimit / sizeof(KGDTENTRY);
    } else {
        maximun = GdtLimit / sizeof(KGDTENTRY);
        maximun++;//һ����128.
    }

    /*
    ��ʾ��ʽ��
    CPU SN Sel        Base              Limit          Type    Pl Size Gran Pres Long Flags
    --- -- ---- ----------------- ----------------- ---------- -- ---- ---- ---- ---- --------

    ע�ͣ�CPU��SN���Լ���ӵġ�SN��Segment Name,�磺CS��DS��FS��.
    */
    KdPrint(("Sel  Base             Limit          Type DPl Size Gran Pres Long Flags\n"));//CPU SN 
    KdPrint(("---- -------- ------------- ------------- --- ---- ---- ---- ---- --------\n"));//--- -- 
    KdPrint(("\n"));

    for (; index < maximun; index++) {
        PKGDTENTRY pkgdte_t = &pkgdte[index];
        SIZE_T Base = 0;
        SIZE_T Limit = 0;
        ULONG  Type = 0;
        char * size = NULL;
        char * Granularity = NULL;
        char * Present = NULL;
        char * LongMode = NULL;
        int    Flags = 0;

        //ע�⣺0x38����ֵ��ͣ�ı仯��
        USHORT  BaseLow = pkgdte_t->BaseLow;
        ULONG   BaseMid = pkgdte_t->HighWord.Bits.BaseMid;
        ULONG   BaseHi = pkgdte_t->HighWord.Bits.BaseHi;
        Base = (BaseHi << 24) + (BaseMid << 16) + BaseLow;//��ʵ��λ����� | ��

        if (pkgdte_t->HighWord.Bits.Granularity && BooleanFlagOn(pkgdte_t->HighWord.Bits.Type, 2)) {//���ڱ�־λ���㷨����Ȩ�����ϡ�
            Limit = pkgdte_t->LimitLow + (pkgdte_t->HighWord.Bits.LimitHi << 16);
            Limit *= PAGE_SIZE;
            Limit += PAGE_SIZE - 1;
        } else {
            Limit = pkgdte_t->LimitLow + (pkgdte_t->HighWord.Bits.LimitHi << 16);
        }

        //if (pkgdte_t->HighWord.Bits.Default_Big && Base)
        //{
        //    //�����λΪ1.��F.
        //    Base += 0xffff0000;
        //}      

        //if (pkgdte_t->Bits.DefaultBig && pkgdte_t->Bits.Granularity)
        //{
        //    //�����λΪ1.��F.
        //    SIZE_T t = Limit;
        //    Limit = (Limit << 12);
        //    Limit += PAGE_SIZE - 1;
        //} 

        Type = pkgdte_t->HighWord.Bits.Type;
        _bittestandreset((LONG *)&Type, 4);//��Ϊ���������Sλ������Ҫ������λ��־��

        if (pkgdte_t->HighWord.Bits.Default_Big) {
            size = "Bg  ";//Big �ӿո���Ϊ�˶�����ʾ��
        } else {
            size = "Nb  ";//Not Big �ӿո���Ϊ�˶�����ʾ��
        }

        if (pkgdte_t->HighWord.Bits.Granularity) {
            Granularity = "Pg  ";//Page �ӿո���Ϊ�˶�����ʾ��
        } else {
            Granularity = "By  ";//Byte �ӿո���Ϊ�˶�����ʾ��
        }

        if (pkgdte_t->HighWord.Bits.Pres) {
            Present = "P   ";//Present �ӿո���Ϊ�˶�����ʾ��
        } else {
            Present = "NP  ";//NO Present �ӿո���Ϊ�˶�����ʾ��
        }

        if (pkgdte_t->HighWord.Bits.Reserved_0) {
            LongMode = "Lo  ";//Long �ӿո���Ϊ�˶�����ʾ��
        } else {
            LongMode = "Nl  ";//NO long �ӿո���Ϊ�˶�����ʾ��
        }

        Flags = (pkgdte_t->HighWord.Bytes.Flags2 >> 4);//ȥ��Segment limit���Ǽ�λ��
        Flags = Flags << 8;
        Flags = Flags + pkgdte_t->HighWord.Bytes.Flags1;

        KdPrint(("%04x %p %p %13s %03x %s %s %s %s 0x%04x\n",
                 index * 8, //sizeof (KGDTENTRY)
                 Base,
                 Limit,
                 SegmentTypes[Type],
                 pkgdte_t->HighWord.Bits.Dpl,
                 size,
                 Granularity,
                 Present,
                 LongMode,
                 Flags
                 ));

        //KdPrint(("��%d��CPU��GDT��Sel:0x%03x, Base:0x%08x, Limit:0x%08x, type:0x%02x, Dpl:0x%x, Pres:0x%x, Sys:0x%x,Default_Big:0x%x, Granularity:0x%x.\n", 
        //    i, index * sizeof (KGDTENTRY), Base, Limit,
        //    pkgdte_t->HighWord.Bits.Type,
        //    pkgdte_t->HighWord.Bits.Dpl,
        //    pkgdte_t->HighWord.Bits.Pres,
        //    pkgdte_t->HighWord.Bits.Sys,
        //    pkgdte_t->HighWord.Bits.Default_Big,
        //    pkgdte_t->HighWord.Bits.Granularity
        //    ));

        /*
        �����Default_Big��Ӧdg�����size.
        �����Sys��Ӧdg�����long.
        Flags��ֵ���ڱ����ӡ�ˣ�����Ͳ��ٴ�ӡ�ˡ�
        */
    }
}
#endif


NTSTATUS TestGdt()
{
    int i = 0;

    KdBreakPoint();

    for (; i < KeNumberProcessors; i++)//KeQueryMaximumProcessorCount()  KeGetCurrentProcessorNumber
    {
        show_gdt(i);
    }

    return STATUS_SUCCESS;
}
