#include "gdt.h"
#include "pcr.h"


#pragma warning(disable:6066)
#pragma warning(disable:26451)


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
根据：Table 3-1. Code- and Data-Segment Types，仿照WINDBG的dg命令定义。
*/
char SegmentTypes[][256] = {
    "<Reserved>",//Data Read-Only缩写是：Data RO，也可认为是： <Reserved>。如果结构（UINT64）全部为零，也可认为是Reserved。
    "Data RO AC",//Data Read-Only, accessed
    "Data RW",//Data Read/Write
    "Data RW AC",//Data Read/Write, accessed
    "Data RO ED",//Data Read-Only, expand-down
    "Data RO ED AC",//Data Read-Only, expand-down, accessed
    "Data RW ED",//Data Read/Write, expand-down
    "Data RW ED AC",//Data Read/Write, expand-down, accessed

    "Code EO",//Code Execute-Only
    "Code EO AC",//Code Execute-Only, accessed
    "Code RE",//Code Execute/Read 加空格以便显示的对齐。
    "Code RE AC",//Code Execute/Read, accessed
    "Code EO CO",//Code Execute-Only, conforming
    "Code EO CO AC",//Code Execute-Only, conforming, accessed
    "Code RE CO",//Code Execute/Read, conforming
    "Code RE CO AC",//Code Execute/Read, conforming, accessed
    "TSS32 Busy ",//这个也可显示只要识别了TSS及内容。
    "TSS32 Avl" //这个在X86上出现了。
};


//#ifdef _X86_
////__forceinline 
//PKPCR KeGetPcr(VOID)
//{
//    return (PKPCR)__readfsdword(FIELD_OFFSET(KPCR, SelfPcr));
//}
//#endif


USHORT NTAPI GetGdtLimit();//汇编函数。


#if defined(_WIN64)
void show_gdt(int i)
/*
i的取值可以是0.
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
    pkgdte = KeGetPcr()->GdtBase;//没有__sgdt,也不用sgdt汇编指令的办法。但是这个获取的没有长度。
    GdtLimit = GetGdtLimit();//一般等于0x7f.
    KeRevertToUserAffinityThread();

    //p = &gdtr.Limit;
    //r = * (SIZE_T *)p;
    //pkgdte = (PKGDTENTRY)r; 

    /*
    其实直接：
    maximun = (idtr.Base + 1) / sizeof(KIDTENTRY);
    也可以。
    maximun一般等于256.
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
    //    maximun++;//一般是128.
    //}

    maximun = (GdtLimit + 1) / sizeof(KGDTENTRY64);

    /*
    显示格式：
    CPU SN Sel        Base              Limit          Type    Pl Size Gran Pres Long Flags
    --- -- ---- ----------------- ----------------- ---------- -- ---- ---- ---- ---- --------

    注释：CPU和SN是自己添加的。SN即Segment Name,如：CS，DS，FS等.
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
            //扩充高位为1.即F.
            Base += 0xffffffff00000000;
        }

        if (pkgdte_t->Bits.DefaultBig && pkgdte_t->Bits.Granularity) {
            //扩充高位为1.即F.
            //SIZE_T t = Limit;
            Limit = (Limit << 12);
            Limit += PAGE_SIZE - 1;
        }

        Type = pkgdte_t->Bits.Type;
        _bittestandreset((LONG *)&Type, 4);//因为这个包含了S位，所以要清除这个位标志。

        if (pkgdte_t->Bits.DefaultBig) {
            size = "Bg  ";//Big 加空格是为了对齐显示。
        } else {
            size = "Nb  ";//Not Big 加空格是为了对齐显示。
        }

        if (pkgdte_t->Bits.Granularity) {
            Granularity = "Pg  ";//Page 加空格是为了对齐显示。
        } else {
            Granularity = "By  ";//Byte 加空格是为了对齐显示。
        }

        if (pkgdte_t->Bits.Present) {
            Present = "P   ";//Present 加空格是为了对齐显示。
        } else {
            Present = "NP  ";//NO Present 加空格是为了对齐显示。
        }

        if (pkgdte_t->Bits.LongMode) {
            LongMode = "Lo  ";//Long 加空格是为了对齐显示。
        } else {
            LongMode = "Nl  ";//NO long 加空格是为了对齐显示。
        }

        Flags = (pkgdte_t->Bytes.Flags2 >> 4);//去掉Segment limit的那几位。
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
        //    KdPrint(("第%d号CPU的GDT的Sel:0x%03x, Base:0x%016p, Limit:0x%016p, type:0x%02x, Dpl:0x%x, Pres:0x%x, Sys:0x%x, LongMode:0x%x, Default_Big:0x%x, Granularity:0x%x.\n", 
        //        i, index * sizeof (KGDTENTRY64), Base, Limit,
        //        pkgdte_t->Bits.Type,
        //        pkgdte_t->Bits.Dpl,
        //        pkgdte_t->Bits.Present,//再打印一次吧！
        //        pkgdte_t->Bits.System,
        //        pkgdte_t->Bits.LongMode,
        //        pkgdte_t->Bits.DefaultBig,
        //        pkgdte_t->Bits.Granularity
        //        ));
        //}
        //else //<Reserved> 
        //{
        //    KdPrint(("第%d号CPU的GDT的Sel:0x%03x is Reserved!\n", i, index * sizeof (KGDTENTRY64)));
        //}


        ////偶尔出现有一个不对，即0x38的值不对，
        //Base = pkgdte_t->BaseLow + (pkgdte_t->HighWord.Bits.BaseHi << 24) + (pkgdte_t->HighWord.Bits.BaseMid << 16);//其实用位与更快 | 。

        //if (pkgdte_t->HighWord.Bits.Granularity && BooleanFlagOn(pkgdte_t->HighWord.Bits.Type, 2 ) ) {//关于标志位及算法，见权威资料。
        //    Limit = pkgdte_t->LimitLow + (pkgdte_t->HighWord.Bits.LimitHi << 16);
        //    Limit *= PAGE_SIZE;
        //    Limit += PAGE_SIZE - 1;
        //} else {
        //    Limit = pkgdte_t->LimitLow + (pkgdte_t->HighWord.Bits.LimitHi << 16);
        //}

        //KdPrint(("第%d号CPU的GDT的Sel:0x%03x, Base:0x%08x, Limit:0x%08x, type:0x%02x, Dpl:0x%x, Pres:0x%x, Sys:0x%x,Default_Big:0x%x, Granularity:0x%x.\n", 
        //    i, index * sizeof (KGDTENTRY), Base, Limit,
        //    pkgdte_t->HighWord.Bits.Type,
        //    pkgdte_t->HighWord.Bits.Dpl,
        //    pkgdte_t->HighWord.Bits.Pres,
        //    pkgdte_t->HighWord.Bits.Sys,
        //    pkgdte_t->HighWord.Bits.Default_Big,
        //    pkgdte_t->HighWord.Bits.Granularity
        //    ));

        /*
        这里的Default_Big对应dg命令的size.
        这里的Sys对应dg命令的long.
        Flags的值等于变相打印了，这里就不再打印了。
        */
    }
}
#else 
void show_gdt(int i)
/*
i的取值可以是0.
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
    pkgdte = KeGetPcr()->GDT;//没有__sgdt,也不用sgdt汇编指令的办法。但是这个获取的没有长度。
    GdtLimit = GetGdtLimit();//一般等于0x3ff.
    KeRevertToUserAffinityThread();

    //p = &gdtr.Limit;
    //r = * (SIZE_T *)p;
    //pkgdte = (PKGDTENTRY)r; 

    /*
    其实直接：
    maximun = (idtr.Base + 1) / sizeof(KIDTENTRY);
    也可以。
    maximun一般等于256.
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
        maximun++;//一般是128.
    }

    /*
    显示格式：
    CPU SN Sel        Base              Limit          Type    Pl Size Gran Pres Long Flags
    --- -- ---- ----------------- ----------------- ---------- -- ---- ---- ---- ---- --------

    注释：CPU和SN是自己添加的。SN即Segment Name,如：CS，DS，FS等.
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

        //注意：0x38处的值不停的变化。
        USHORT  BaseLow = pkgdte_t->BaseLow;
        ULONG   BaseMid = pkgdte_t->HighWord.Bits.BaseMid;
        ULONG   BaseHi = pkgdte_t->HighWord.Bits.BaseHi;
        Base = (BaseHi << 24) + (BaseMid << 16) + BaseLow;//其实用位与更快 | 。

        if (pkgdte_t->HighWord.Bits.Granularity && BooleanFlagOn(pkgdte_t->HighWord.Bits.Type, 2)) {//关于标志位及算法，见权威资料。
            Limit = pkgdte_t->LimitLow + (pkgdte_t->HighWord.Bits.LimitHi << 16);
            Limit *= PAGE_SIZE;
            Limit += PAGE_SIZE - 1;
        } else {
            Limit = pkgdte_t->LimitLow + (pkgdte_t->HighWord.Bits.LimitHi << 16);
        }

        //if (pkgdte_t->HighWord.Bits.Default_Big && Base)
        //{
        //    //扩充高位为1.即F.
        //    Base += 0xffff0000;
        //}      

        //if (pkgdte_t->Bits.DefaultBig && pkgdte_t->Bits.Granularity)
        //{
        //    //扩充高位为1.即F.
        //    SIZE_T t = Limit;
        //    Limit = (Limit << 12);
        //    Limit += PAGE_SIZE - 1;
        //} 

        Type = pkgdte_t->HighWord.Bits.Type;
        _bittestandreset((LONG *)&Type, 4);//因为这个包含了S位，所以要清除这个位标志。

        if (pkgdte_t->HighWord.Bits.Default_Big) {
            size = "Bg  ";//Big 加空格是为了对齐显示。
        } else {
            size = "Nb  ";//Not Big 加空格是为了对齐显示。
        }

        if (pkgdte_t->HighWord.Bits.Granularity) {
            Granularity = "Pg  ";//Page 加空格是为了对齐显示。
        } else {
            Granularity = "By  ";//Byte 加空格是为了对齐显示。
        }

        if (pkgdte_t->HighWord.Bits.Pres) {
            Present = "P   ";//Present 加空格是为了对齐显示。
        } else {
            Present = "NP  ";//NO Present 加空格是为了对齐显示。
        }

        if (pkgdte_t->HighWord.Bits.Reserved_0) {
            LongMode = "Lo  ";//Long 加空格是为了对齐显示。
        } else {
            LongMode = "Nl  ";//NO long 加空格是为了对齐显示。
        }

        Flags = (pkgdte_t->HighWord.Bytes.Flags2 >> 4);//去掉Segment limit的那几位。
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

        //KdPrint(("第%d号CPU的GDT的Sel:0x%03x, Base:0x%08x, Limit:0x%08x, type:0x%02x, Dpl:0x%x, Pres:0x%x, Sys:0x%x,Default_Big:0x%x, Granularity:0x%x.\n", 
        //    i, index * sizeof (KGDTENTRY), Base, Limit,
        //    pkgdte_t->HighWord.Bits.Type,
        //    pkgdte_t->HighWord.Bits.Dpl,
        //    pkgdte_t->HighWord.Bits.Pres,
        //    pkgdte_t->HighWord.Bits.Sys,
        //    pkgdte_t->HighWord.Bits.Default_Big,
        //    pkgdte_t->HighWord.Bits.Granularity
        //    ));

        /*
        这里的Default_Big对应dg命令的size.
        这里的Sys对应dg命令的long.
        Flags的值等于变相打印了，这里就不再打印了。
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
