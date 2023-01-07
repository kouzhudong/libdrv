/*
功能：显示每个CPU的GDT信息。
注释：一下结构摘自WRK。

made by correy.
made at 2015.01.11.
*/

#pragma once

#include "pch.h"

class gdt
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


#if defined(_AMD64_) || defined(_IA64_) //defined(_WIN64)

// Special Registers for AMD64.
typedef struct _AMD64_DESCRIPTOR {
    USHORT  Pad[3];
    USHORT  Limit;
    ULONG64 Base;
} AMD64_DESCRIPTOR, * PAMD64_DESCRIPTOR;

typedef union _KGDTENTRY64 {
    struct {
        USHORT  LimitLow;
        USHORT  BaseLow;
        union {
            struct {
                UCHAR   BaseMiddle;
                UCHAR   Flags1;
                UCHAR   Flags2;
                UCHAR   BaseHigh;
            } Bytes;

            struct {
                ULONG   BaseMiddle : 8;
                ULONG   Type : 5;//把S位包含进去了，也就是是否为系统段描述符的位。
                ULONG   Dpl : 2;
                ULONG   Present : 1;
                ULONG   LimitHigh : 4;
                ULONG   System : 1;//即AVL，系统软件自定义的。
                ULONG   LongMode : 1;
                ULONG   DefaultBig : 1;//即INTEL的D/B (default operation size/default stack pointer size and/or upper bound) flag。
                ULONG   Granularity : 1;
                ULONG   BaseHigh : 8;
            } Bits;
        };

        //ULONG BaseUpper;/*经观察，64下的结构的长度是6字节，不是上面定义的16字节。*/
        //ULONG MustBeZero;
    };

    //ULONG64 Alignment;
} KGDTENTRY64, * PKGDTENTRY64;


#else 

// Special Registers for i386
typedef struct _X86_DESCRIPTOR {
    USHORT  Pad;
    USHORT  Limit;
    ULONG   Base;
} X86_DESCRIPTOR, * PX86_DESCRIPTOR;

typedef struct _X86_KSPECIAL_REGISTERS {
    ULONG Cr0;
    ULONG Cr2;
    ULONG Cr3;
    ULONG Cr4;
    ULONG KernelDr0;
    ULONG KernelDr1;
    ULONG KernelDr2;
    ULONG KernelDr3;
    ULONG KernelDr6;
    ULONG KernelDr7;
    X86_DESCRIPTOR Gdtr;
    X86_DESCRIPTOR Idtr;//由此可知，GDT和IDT的结构是一样的。
    USHORT Tr;
    USHORT Ldtr;
    ULONG Reserved[6];
} X86_KSPECIAL_REGISTERS, * PX86_KSPECIAL_REGISTERS;

// GDT Entry
typedef struct _KGDTENTRY {
    USHORT  LimitLow;
    USHORT  BaseLow;
    union {
        struct {
            UCHAR   BaseMid;
            UCHAR   Flags1;     // Declare as bytes to avoid alignment
            UCHAR   Flags2;     // Problems.
            UCHAR   BaseHi;
        } Bytes;
        struct {
            ULONG   BaseMid : 8;
            ULONG   Type : 5;//把S位包含进去了，也就是是否为系统段描述符的位。
            ULONG   Dpl : 2;
            ULONG   Pres : 1;
            ULONG   LimitHi : 4;
            ULONG   Sys : 1;//即AVL，系统软件自定义的。
            ULONG   Reserved_0 : 1;//LongMode
            ULONG   Default_Big : 1;//即INTEL的D/B (default operation size/default stack pointer size and/or upper bound) flag。
            ULONG   Granularity : 1;
            ULONG   BaseHi : 8;
        } Bits;
    } HighWord;
} KGDTENTRY, * PKGDTENTRY;

#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
0: kd> dg 0 256
                                  P Si Gr Pr Lo
Sel    Base     Limit     Type    l ze an es ng Flags
---- -------- -------- ---------- - -- -- -- -- --------
0000 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
0008 00000000 ffffffff Code RE Ac 0 Bg Pg P  Nl 00000c9b
0010 00000000 ffffffff Data RW Ac 0 Bg Pg P  Nl 00000c93
0018 00000000 ffffffff Code RE Ac 3 Bg Pg P  Nl 00000cfb
0020 00000000 ffffffff Data RW Ac 3 Bg Pg P  Nl 00000cf3
0028 80042000 000020ab TSS32 Busy 0 Nb By P  Nl 0000008b
0030 ffdff000 00001fff Data RW Ac 0 Bg Pg P  Nl 00000c93
0038 00000000 00000fff Data RW Ac 3 Bg By P  Nl 000004f3
0040 00000400 0000ffff Data RW    3 Nb By P  Nl 000000f2
0048 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
0050 80552700 00000068 TSS32 Avl  0 Nb By P  Nl 00000089
0058 80552768 00000068 TSS32 Avl  0 Nb By P  Nl 00000089
0060 00022f40 0000ffff Data RW Ac 0 Nb By P  Nl 00000093
0068 000b8000 00003fff Data RW    0 Nb By P  Nl 00000092
0070 ffff7000 000003ff Data RW    0 Nb By P  Nl 00000092
0078 80400000 0000ffff Code RE    0 Nb By P  Nl 0000009a
0080 80400000 0000ffff Data RW    0 Nb By P  Nl 00000092
0088 00000000 00000000 Data RW    0 Nb By P  Nl 00000092
0090 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
0098 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
00A0 82181238 00000068 TSS32 Avl  0 Nb By P  Nl 00000089
00A8 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
00B0 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
00B8 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
00C0 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
00C8 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
00D0 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
00D8 00000000 00000000 <Reserved> 0 Nb By Np Nl 00000000
00E0 f851f000 0000ffff Code RE Ac 0 Nb By P  Nl 0000009f
00E8 00000000 0000ffff Data RW    0 Nb By P  Nl 00000092
00F0 804fd040 000003b7 Code EO    0 Nb By P  Nl 00000098
00F8 00000000 0000ffff Data RW    0 Nb By P  Nl 00000092
0100 ba4bd400 0000ffff Data RW Ac 0 Bg By P  Nl 00000493
0108 ba4bd400 0000ffff Data RW Ac 0 Bg By P  Nl 00000493
0110 ba4bd400 0000ffff Data RW Ac 0 Bg By P  Nl 00000493
0118 00008003 0000f120 <Reserved> 0 Nb By Np Nl 00000000
0120 00008003 0000f128 <Reserved> 0 Nb By Np Nl 00000000
0128 00008003 0000f130 <Reserved> 0 Nb By Np Nl 00000000
0130 00008003 0000f138 <Reserved> 0 Nb By Np Nl 00000000
0138 00008003 0000f140 <Reserved> 0 Nb By Np Nl 00000000
0140 00008003 0000f148 <Reserved> 0 Nb By Np Nl 00000000
0148 00008003 0000f150 <Reserved> 0 Nb By Np Nl 00000000
0150 00008003 0000f158 <Reserved> 0 Nb By Np Nl 00000000
0158 00008003 0000f160 <Reserved> 0 Nb By Np Nl 00000000
0160 00008003 0000f168 <Reserved> 0 Nb By Np Nl 00000000
0168 00008003 0000f170 <Reserved> 0 Nb By Np Nl 00000000
0170 00008003 0000f178 <Reserved> 0 Nb By Np Nl 00000000
0178 00008003 0000f180 <Reserved> 0 Nb By Np Nl 00000000
0180 00008003 0000f188 <Reserved> 0 Nb By Np Nl 00000000
0188 00008003 0000f190 <Reserved> 0 Nb By Np Nl 00000000
0190 00008003 0000f198 <Reserved> 0 Nb By Np Nl 00000000
0198 00008003 0000f1a0 <Reserved> 0 Nb By Np Nl 00000000
01A0 00008003 0000f1a8 <Reserved> 0 Nb By Np Nl 00000000
01A8 00008003 0000f1b0 <Reserved> 0 Nb By Np Nl 00000000
01B0 00008003 0000f1b8 <Reserved> 0 Nb By Np Nl 00000000
01B8 00008003 0000f1c0 <Reserved> 0 Nb By Np Nl 00000000
01C0 00008003 0000f1c8 <Reserved> 0 Nb By Np Nl 00000000
01C8 00008003 0000f1d0 <Reserved> 0 Nb By Np Nl 00000000
01D0 00008003 0000f1d8 <Reserved> 0 Nb By Np Nl 00000000
01D8 00008003 0000f1e0 <Reserved> 0 Nb By Np Nl 00000000
01E0 00008003 0000f1e8 <Reserved> 0 Nb By Np Nl 00000000
01E8 00008003 0000f1f0 <Reserved> 0 Nb By Np Nl 00000000
01F0 00008003 0000f1f8 <Reserved> 0 Nb By Np Nl 00000000
01F8 00008003 0000f200 <Reserved> 0 Nb By Np Nl 00000000
0200 00008003 0000f208 <Reserved> 0 Nb By Np Nl 00000000
0208 00008003 0000f210 <Reserved> 0 Nb By Np Nl 00000000
0210 00008003 0000f218 <Reserved> 0 Nb By Np Nl 00000000
0218 00008003 0000f220 <Reserved> 0 Nb By Np Nl 00000000
0220 00008003 0000f228 <Reserved> 0 Nb By Np Nl 00000000
0228 00008003 0000f230 <Reserved> 0 Nb By Np Nl 00000000
0230 00008003 0000f238 <Reserved> 0 Nb By Np Nl 00000000
0238 00008003 0000f240 <Reserved> 0 Nb By Np Nl 00000000
0240 00008003 0000f248 <Reserved> 0 Nb By Np Nl 00000000
0248 00008003 0000f250 <Reserved> 0 Nb By Np Nl 00000000
0250 00008003 0000f258 <Reserved> 0 Nb By Np Nl 00000000
0: kd> dg 0 256
                                                    P Si Gr Pr Lo
Sel        Base              Limit          Type    l ze an es ng Flags
---- ----------------- ----------------- ---------- - -- -- -- -- --------
0000 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
0008 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
0010 00000000`00000000 00000000`00000000 Code RE Ac 0 Nb By P  Lo 0000029b
0018 00000000`00000000 00000000`ffffffff Data RW Ac 0 Bg Pg P  Nl 00000c93
0020 00000000`00000000 00000000`ffffffff Code RE    3 Bg Pg P  Nl 00000cfa
0028 00000000`00000000 00000000`ffffffff Data RW Ac 3 Bg Pg P  Nl 00000cf3
0030 00000000`00000000 00000000`00000000 Code RE Ac 3 Nb By P  Lo 000002fb
0038 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
0040 00000000`01794080 00000000`00000067 TSS32 Busy 0 Nb By P  Nl 0000008b
0048 00000000`0000ffff 00000000`0000f800 <Reserved> 0 Nb By Np Nl 00000000
0050 ffffffff`fffa0000 00000000`00003c00 Data RW Ac 3 Bg By P  Nl 000004f3
0058 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
0060 00000000`00000000 00000000`ffffffff Code RE    0 Bg Pg P  Nl 00000c9a
0068 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
0070 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
0078 00000000`00000000 00000000`00000000 <Reserved> 0 Nb By Np Nl 00000000
0080 Unable to get descriptor

kd> r GDTR
gdtr=fffff80004289000
kd> db fffff80004289000
fffff800`04289000  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
fffff800`04289010  00 00 00 00 00 9b 20 00-ff ff 00 00 00 93 cf 00  ...... .........
fffff800`04289020  ff ff 00 00 00 fb cf 00-ff ff 00 00 00 f3 cf 00  ................
fffff800`04289030  00 00 00 00 00 fb 20 00-00 00 00 00 00 00 00 00  ...... .........
fffff800`04289040  67 00 70 a0 28 8b 00 04-00 f8 ff ff 00 00 00 00  g.p.(...........
fffff800`04289050  00 3c 00 00 fe f3 40 ff-00 00 00 00 00 00 00 00  .<....@.........
fffff800`04289060  ff ff 00 00 00 9a cf 00-00 00 00 00 00 00 00 00  ................
fffff800`04289070  40 bf 10 00 00 8e a5 01-00 f8 ff ff 00 00 00 00  @...............
kd> r gdtl
gdtl=006f

kd> dg @cs
                                                    P Si Gr Pr Lo
Sel        Base              Limit          Type    l ze an es ng Flags
---- ----------------- ----------------- ---------- - -- -- -- -- --------
0010 00000000`00000000 00000000`00000000 Code RE Ac 0 Nb By P  Lo 0000029b
kd> r cs
cs=0010
*/


//////////////////////////////////////////////////////////////////////////////////////////////////
