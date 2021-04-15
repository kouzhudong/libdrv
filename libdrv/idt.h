/*
���ܣ���ʾÿ��CPU��IDT��Ϣ��
ע�ͣ�һ�½ṹժ��WRK��

�ο���
http://uninformed.org/index.cgi?v=8&a=2&p=8
http://resources.infosecinstitute.com/hooking-idt/

made by correy.
made at 2015.01.05.
*/

#pragma once

#include "pch.h"

class idt
{

};


//////////////////////////////////////////////////////////////////////////////////////////////////


typedef
VOID
(*PKINTERRUPT_ROUTINE) (
    VOID
    );

struct _KINTERRUPT;//�ṹ����ǰ�á�

// begin_ntddk begin_wdm begin_ntifs begin_ntosp

typedef
BOOLEAN
(*PKSERVICE_ROUTINE) (
    IN struct _KINTERRUPT * Interrupt,
    IN PVOID ServiceContext
    );

#define NORMAL_DISPATCH_LENGTH 106                  // ntddk wdm
#define DISPATCH_LENGTH NORMAL_DISPATCH_LENGTH      // ntddk wdm

// Interrupt object
typedef struct _KINTERRUPT {
    CSHORT Type;
    CSHORT Size;
    LIST_ENTRY InterruptListEntry;
    PKSERVICE_ROUTINE ServiceRoutine;
    PVOID ServiceContext;
    KSPIN_LOCK SpinLock;
    ULONG TickCount;
    PKSPIN_LOCK ActualLock;
    PKINTERRUPT_ROUTINE DispatchAddress;
    ULONG Vector;
    KIRQL Irql;
    KIRQL SynchronizeIrql;
    BOOLEAN FloatingSave;
    BOOLEAN Connected;
    CCHAR Number;
    BOOLEAN ShareVector;
    KINTERRUPT_MODE Mode;
    ULONG ServiceCount;
    ULONG DispatchCount;

#if defined(_AMD64_)
    PKTRAP_FRAME TrapFrame;
    PVOID Reserved;
    ULONG DispatchCode[DISPATCH_LENGTH];
#else
    ULONG DispatchCode[DISPATCH_LENGTH];
#endif

} KINTERRUPT;



#if defined(_WIN64)

// Special Registers for AMD64.
typedef struct _AMD64_DESCRIPTOR {
    USHORT  Pad[3];
    USHORT  Limit;
    ULONG64 Base;
} AMD64_DESCRIPTOR, * PAMD64_DESCRIPTOR;

// Define Interrupt Descriptor Table (IDT) entry structure and constants.
typedef union _KIDTENTRY64 {
    struct {
        USHORT OffsetLow;
        USHORT Selector;
        USHORT IstIndex : 3;
        USHORT Reserved0 : 5;
        USHORT Type : 5;
        USHORT Dpl : 2;
        USHORT Present : 1;
        USHORT OffsetMiddle;
        ULONG OffsetHigh;
        ULONG Reserved1;
    };

    ULONG64 Alignment;
} KIDTENTRY64, * PKIDTENTRY64;

typedef union _KIDT_HANDLER_ADDRESS {
    struct {
        USHORT OffsetLow;
        USHORT OffsetMiddle;
        ULONG OffsetHigh;
    };

    ULONG64 Address;
} KIDT_HANDLER_ADDRESS, * PKIDT_HANDLER_ADDRESS;

#define KiGetIdtFromVector(Vector)                  \
    &KeGetPcr()->IdtBase[HalVectorToIDTEntry(Vector)]

#define KeGetIdtHandlerAddress(Vector,Addr) {       \
    KIDT_HANDLER_ADDRESS Handler;                   \
    PKIDTENTRY64 Idt;                               \
    \
    Idt = KiGetIdtFromVector(Vector);               \
    Handler.OffsetLow = Idt->OffsetLow;             \
    Handler.OffsetMiddle = Idt->OffsetMiddle;       \
    Handler.OffsetHigh = Idt->OffsetHigh;           \
    *(Addr) = (PVOID)(Handler.Address);             \
}

#define KeSetIdtHandlerAddress(Vector,Addr) {      \
    KIDT_HANDLER_ADDRESS Handler;                  \
    PKIDTENTRY64 Idt;                              \
    \
    Idt = KiGetIdtFromVector(Vector);              \
    Handler.Address = (ULONG64)(Addr);             \
    Idt->OffsetLow = Handler.OffsetLow;            \
    Idt->OffsetMiddle = Handler.OffsetMiddle;      \
    Idt->OffsetHigh = Handler.OffsetHigh;          \
}

#else 

// Special Registers for i386
typedef struct _X86_DESCRIPTOR {
    USHORT  Pad;
    USHORT  Limit;
    ULONG   Base;
} X86_DESCRIPTOR, * PX86_DESCRIPTOR;


// Entry of Interrupt Descriptor Table (IDTENTRY)
typedef struct _KIDTENTRY {
    USHORT Offset;
    USHORT Selector;
    USHORT Access;
    USHORT ExtendedOffset;
} KIDTENTRY;
typedef KIDTENTRY * PKIDTENTRY;

// begin_nthal
//
// Macro to set address of a trap/interrupt handler to IDT
//
#define KiSetHandlerAddressToIDT(Vector, HandlerAddress) {\
    UCHAR IDTEntry = HalVectorToIDTEntry(Vector); \
    ULONG Ha = (ULONG)HandlerAddress; \
    KeGetPcr()->IDT[IDTEntry].ExtendedOffset = HIGHWORD(Ha); \
    KeGetPcr()->IDT[IDTEntry].Offset = LOWWORD(Ha); \
}

//
// Macro to return address of a trap/interrupt handler in IDT
//
#define KiReturnHandlerAddressFromIDT(Vector) \
   MAKEULONG(KiPcr()->IDT[HalVectorToIDTEntry(Vector)].ExtendedOffset, KiPcr()->IDT[HalVectorToIDTEntry(Vector)].Offset)

#endif


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
0: kd> !idt

Dumping IDT: 8003f400

455901d000000037:	806e7864 hal!PicSpuriousService37
455901d00000003d:	806e8e2c hal!HalpApcInterrupt
455901d000000041:	806e8c88 hal!HalpDispatchInterrupt
455901d000000050:	806e793c hal!HalpApicRebootService
455901d000000062:	81fd6044 atapi!IdePortInterrupt (KINTERRUPT 81fd6008)
455901d000000063:	81f1ebec portcls!CKsShellRequestor::`vector deleting destructor'+0x26 (KINTERRUPT 81f1ebb0)
455901d000000073:	81d17bec SCSIPORT!ScsiPortInterrupt (KINTERRUPT 81d17bb0)
455901d000000082:	81e26bec atapi!IdePortInterrupt (KINTERRUPT 81e26bb0)
455901d000000083:	81c42044 vmci!DllUnload+0x7d6 (KINTERRUPT 81c42008)
             VIDEOPRT!pVideoPortInterrupt (KINTERRUPT 81d0e758)
455901d000000093:	81fcd684 i8042prt!I8042KeyboardInterruptService (KINTERRUPT 81fcd648)
455901d0000000a3:	81d0ebec i8042prt!I8042MouseInterruptService (KINTERRUPT 81d0ebb0)
455901d0000000b1:	820ce8cc ACPI!ACPIInterruptServiceRoutine (KINTERRUPT 820ce890)
455901d0000000b4:	81e1e9ec NDIS!ndisMIsr (KINTERRUPT 81e1e9b0)
455901d0000000c1:	806e7ac0 hal!HalpBroadcastCallService
455901d0000000d1:	806e6e54 hal!HalpClockInterrupt
455901d0000000e1:	806e8048 hal!HalpIpiHandler
455901d0000000e3:	806e7dac hal!HalpLocalApicErrorService
455901d0000000fd:	806e85a8 hal!HalpProfileInterrupt
455901d0000000fe:	806e8748 hal!HalpPerfInterrupt

0: kd> !pcr
KPCR for Processor 0 at ffdff000:
    Major 1 Minor 1
    NtTib.ExceptionList: 80551cb0
        NtTib.StackBase: 805524f0
       NtTib.StackLimit: 8054f700
     NtTib.SubSystemTib: 00000000
          NtTib.Version: 00000000
      NtTib.UserPointer: 00000000
          NtTib.SelfTib: 00000000

                SelfPcr: ffdff000
                   Prcb: ffdff120
                   Irql: 00000000
                    IRR: 00000000
                    IDR: ffffffff
          InterruptMode: 00000000
                    IDT: 8003f400
                    GDT: 8003f000
                    TSS: 80042000

          CurrentThread: 8055ce60
             NextThread: 00000000
             IdleThread: 8055ce60

              DpcQueue:
0: kd> r idtr
idtr=8003f400
0: kd> dw idtr
8003f400  3360 0008 8e00 8054 34dc 0008 8e00 8054
8003f410  113e 0058 8500 0000 38f0 0008 ee00 8054
8003f420  3a70 0008 ee00 8054 3bd0 0008 8e00 8054
8003f430  3d44 0008 8e00 8054 43bc 0008 8e00 8054
8003f440  1198 0050 8500 0000 47c0 0008 8e00 8054
8003f450  48e0 0008 8e00 8054 4a20 0008 8e00 8054
8003f460  4c80 0008 8e00 8054 4f6c 0008 8e00 8054
8003f470  568c 0008 8e00 8054 590c 0008 8e00 8054
0: kd> u 80543360
nt!KiTrap00:
80543360 6a00            push    0
80543362 66c74424020000  mov     word ptr [esp+2],0
80543369 55              push    ebp
8054336a 53              push    ebx
8054336b 56              push    esi
8054336c 57              push    edi
8054336d 0fa0            push    fs
8054336f bb30000000      mov     ebx,30h
0: kd> u 805434dc
nt!KiTrap01:
805434dc 6a00            push    0
805434de 66c74424020000  mov     word ptr [esp+2],0
805434e5 55              push    ebp
805434e6 53              push    ebx
805434e7 56              push    esi
805434e8 57              push    edi
805434e9 0fa0            push    fs
805434eb bb30000000      mov     ebx,30h
1: kd> !idt -a

Dumping IDT: f8733590

2d65dee600000000:	80543360 nt!KiTrap00
2d65dee600000001:	805434dc nt!KiTrap01
2d65dee600000002:	Task Selector = 0x0058
2d65dee600000003:	805438f0 nt!KiTrap03
2d65dee600000004:	80543a70 nt!KiTrap04
2d65dee600000005:	80543bd0 nt!KiTrap05
2d65dee600000006:	80543d44 nt!KiTrap06
2d65dee600000007:	805443bc nt!KiTrap07
2d65dee600000008:	Task Selector = 0x0050
2d65dee600000009:	805447c0 nt!KiTrap09
2d65dee60000000a:	805448e0 nt!KiTrap0A
2d65dee60000000b:	80544a20 nt!KiTrap0B
2d65dee60000000c:	80544c80 nt!KiTrap0C
2d65dee60000000d:	80544f6c nt!KiTrap0D
2d65dee60000000e:	8054568c nt!KiTrap0E
2d65dee60000000f:	8054590c nt!KiTrap0F
2d65dee600000010:	80545a2c nt!KiTrap10
2d65dee600000011:	80545b68 nt!KiTrap11
2d65dee600000012:	Task Selector = 0x00A0
2d65dee600000013:	80545cd0 nt!KiTrap13
2d65dee600000014:	8054590c nt!KiTrap0F
2d65dee600000015:	8054590c nt!KiTrap0F
2d65dee600000016:	8054590c nt!KiTrap0F
2d65dee600000017:	8054590c nt!KiTrap0F
2d65dee600000018:	8054590c nt!KiTrap0F
2d65dee600000019:	8054590c nt!KiTrap0F
2d65dee60000001a:	8054590c nt!KiTrap0F
2d65dee60000001b:	8054590c nt!KiTrap0F
2d65dee60000001c:	8054590c nt!KiTrap0F
2d65dee60000001d:	8054590c nt!KiTrap0F
2d65dee60000001e:	8054590c nt!KiTrap0F
2d65dee60000001f:	806e810c hal!HalpApicSpuriousService
2d65dee600000020:	00000000
2d65dee600000021:	00000000
2d65dee600000022:	00000000
2d65dee600000023:	00000000
2d65dee600000024:	00000000
2d65dee600000025:	00000000
2d65dee600000026:	00000000
2d65dee600000027:	00000000
2d65dee600000028:	00000000
2d65dee600000029:	00000000
2d65dee60000002a:	80542b8e nt!KiGetTickCount
2d65dee60000002b:	80542c90 nt!KiCallbackReturn
2d65dee60000002c:	80542e40 nt!KiSetLowWaitHighThread
2d65dee60000002d:	805437cc nt!KiDebugService
2d65dee60000002e:	80542611 nt!KiSystemService
2d65dee60000002f:	8054590c nt!KiTrap0F
2d65dee600000030:	80541cd0 nt!KiStartUnexpectedRange
2d65dee600000031:	80541cda nt!KiUnexpectedInterrupt1
2d65dee600000032:	80541ce4 nt!KiUnexpectedInterrupt2
2d65dee600000033:	80541cee nt!KiUnexpectedInterrupt3
2d65dee600000034:	80541cf8 nt!KiUnexpectedInterrupt4
2d65dee600000035:	80541d02 nt!KiUnexpectedInterrupt5
2d65dee600000036:	80541d0c nt!KiUnexpectedInterrupt6
2d65dee600000037:	806e7864 hal!PicSpuriousService37
2d65dee600000038:	80541d20 nt!KiUnexpectedInterrupt8
2d65dee600000039:	80541d2a nt!KiUnexpectedInterrupt9
2d65dee60000003a:	80541d34 nt!KiUnexpectedInterrupt10
2d65dee60000003b:	80541d3e nt!KiUnexpectedInterrupt11
2d65dee60000003c:	80541d48 nt!KiUnexpectedInterrupt12
2d65dee60000003d:	806e8e2c hal!HalpApcInterrupt
2d65dee60000003e:	80541d5c nt!KiUnexpectedInterrupt14
2d65dee60000003f:	80541d66 nt!KiUnexpectedInterrupt15
2d65dee600000040:	80541d70 nt!KiUnexpectedInterrupt16
2d65dee600000041:	806e8c88 hal!HalpDispatchInterrupt
2d65dee600000042:	80541d84 nt!KiUnexpectedInterrupt18
2d65dee600000043:	80541d8e nt!KiUnexpectedInterrupt19
2d65dee600000044:	80541d98 nt!KiUnexpectedInterrupt20
2d65dee600000045:	80541da2 nt!KiUnexpectedInterrupt21
2d65dee600000046:	80541dac nt!KiUnexpectedInterrupt22
2d65dee600000047:	80541db6 nt!KiUnexpectedInterrupt23
2d65dee600000048:	80541dc0 nt!KiUnexpectedInterrupt24
2d65dee600000049:	80541dca nt!KiUnexpectedInterrupt25
2d65dee60000004a:	80541dd4 nt!KiUnexpectedInterrupt26
2d65dee60000004b:	80541dde nt!KiUnexpectedInterrupt27
2d65dee60000004c:	80541de8 nt!KiUnexpectedInterrupt28
2d65dee60000004d:	80541df2 nt!KiUnexpectedInterrupt29
2d65dee60000004e:	80541dfc nt!KiUnexpectedInterrupt30
2d65dee60000004f:	80541e06 nt!KiUnexpectedInterrupt31
2d65dee600000050:	806e793c hal!HalpApicRebootService
2d65dee600000051:	80541e1a nt!KiUnexpectedInterrupt33
2d65dee600000052:	80541e24 nt!KiUnexpectedInterrupt34
2d65dee600000053:	80541e2e nt!KiUnexpectedInterrupt35
2d65dee600000054:	80541e38 nt!KiUnexpectedInterrupt36
2d65dee600000055:	80541e42 nt!KiUnexpectedInterrupt37
2d65dee600000056:	80541e4c nt!KiUnexpectedInterrupt38
2d65dee600000057:	80541e56 nt!KiUnexpectedInterrupt39
2d65dee600000058:	80541e60 nt!KiUnexpectedInterrupt40
2d65dee600000059:	80541e6a nt!KiUnexpectedInterrupt41
2d65dee60000005a:	80541e74 nt!KiUnexpectedInterrupt42
2d65dee60000005b:	80541e7e nt!KiUnexpectedInterrupt43
2d65dee60000005c:	80541e88 nt!KiUnexpectedInterrupt44
2d65dee60000005d:	80541e92 nt!KiUnexpectedInterrupt45
2d65dee60000005e:	80541e9c nt!KiUnexpectedInterrupt46
2d65dee60000005f:	80541ea6 nt!KiUnexpectedInterrupt47
2d65dee600000060:	80541eb0 nt!KiUnexpectedInterrupt48
2d65dee600000061:	80541eba nt!KiUnexpectedInterrupt49
2d65dee600000062:	8208e63c atapi!IdePortInterrupt (KINTERRUPT 8208e600)
2d65dee600000063:	82070c74 portcls!CKsShellRequestor::`vector deleting destructor'+0x26 (KINTERRUPT 82070c38)
2d65dee600000064:	80541ed8 nt!KiUnexpectedInterrupt52
2d65dee600000065:	80541ee2 nt!KiUnexpectedInterrupt53
2d65dee600000066:	80541eec nt!KiUnexpectedInterrupt54
2d65dee600000067:	80541ef6 nt!KiUnexpectedInterrupt55
2d65dee600000068:	80541f00 nt!KiUnexpectedInterrupt56
2d65dee600000069:	80541f0a nt!KiUnexpectedInterrupt57
2d65dee60000006a:	80541f14 nt!KiUnexpectedInterrupt58
2d65dee60000006b:	80541f1e nt!KiUnexpectedInterrupt59
2d65dee60000006c:	80541f28 nt!KiUnexpectedInterrupt60
2d65dee60000006d:	80541f32 nt!KiUnexpectedInterrupt61
2d65dee60000006e:	80541f3c nt!KiUnexpectedInterrupt62
2d65dee60000006f:	80541f46 nt!KiUnexpectedInterrupt63
2d65dee600000070:	80541f50 nt!KiUnexpectedInterrupt64
2d65dee600000071:	80541f5a nt!KiUnexpectedInterrupt65
2d65dee600000072:	80541f64 nt!KiUnexpectedInterrupt66
2d65dee600000073:	81f80bbc SCSIPORT!ScsiPortInterrupt (KINTERRUPT 81f80b80)
2d65dee600000074:	80541f78 nt!KiUnexpectedInterrupt68
2d65dee600000075:	80541f82 nt!KiUnexpectedInterrupt69
2d65dee600000076:	80541f8c nt!KiUnexpectedInterrupt70
2d65dee600000077:	80541f96 nt!KiUnexpectedInterrupt71
2d65dee600000078:	80541fa0 nt!KiUnexpectedInterrupt72
2d65dee600000079:	80541faa nt!KiUnexpectedInterrupt73
2d65dee60000007a:	80541fb4 nt!KiUnexpectedInterrupt74
2d65dee60000007b:	80541fbe nt!KiUnexpectedInterrupt75
2d65dee60000007c:	80541fc8 nt!KiUnexpectedInterrupt76
2d65dee60000007d:	80541fd2 nt!KiUnexpectedInterrupt77
2d65dee60000007e:	80541fdc nt!KiUnexpectedInterrupt78
2d65dee60000007f:	80541fe6 nt!KiUnexpectedInterrupt79
2d65dee600000080:	80541ff0 nt!KiUnexpectedInterrupt80
2d65dee600000081:	80541ffa nt!KiUnexpectedInterrupt81
2d65dee600000082:	81f99bbc atapi!IdePortInterrupt (KINTERRUPT 81f99b80)
2d65dee600000083:	81ccd48c vmci!DllUnload+0x7d6 (KINTERRUPT 81ccd450)
             VIDEOPRT!pVideoPortInterrupt (KINTERRUPT 82091ca0)
2d65dee600000084:	80542018 nt!KiUnexpectedInterrupt84
2d65dee600000085:	80542022 nt!KiUnexpectedInterrupt85
2d65dee600000086:	8054202c nt!KiUnexpectedInterrupt86
2d65dee600000087:	80542036 nt!KiUnexpectedInterrupt87
2d65dee600000088:	80542040 nt!KiUnexpectedInterrupt88
2d65dee600000089:	8054204a nt!KiUnexpectedInterrupt89
2d65dee60000008a:	80542054 nt!KiUnexpectedInterrupt90
2d65dee60000008b:	8054205e nt!KiUnexpectedInterrupt91
2d65dee60000008c:	80542068 nt!KiUnexpectedInterrupt92
2d65dee60000008d:	80542072 nt!KiUnexpectedInterrupt93
2d65dee60000008e:	8054207c nt!KiUnexpectedInterrupt94
2d65dee60000008f:	80542086 nt!KiUnexpectedInterrupt95
2d65dee600000090:	80542090 nt!KiUnexpectedInterrupt96
2d65dee600000091:	8054209a nt!KiUnexpectedInterrupt97
2d65dee600000092:	805420a4 nt!KiUnexpectedInterrupt98
2d65dee600000093:	81c7435c i8042prt!I8042KeyboardInterruptService (KINTERRUPT 81c74320)
2d65dee600000094:	805420b8 nt!KiUnexpectedInterrupt100
2d65dee600000095:	805420c2 nt!KiUnexpectedInterrupt101
2d65dee600000096:	805420cc nt!KiUnexpectedInterrupt102
2d65dee600000097:	805420d6 nt!KiUnexpectedInterrupt103
2d65dee600000098:	805420e0 nt!KiUnexpectedInterrupt104
2d65dee600000099:	805420ea nt!KiUnexpectedInterrupt105
2d65dee60000009a:	805420f4 nt!KiUnexpectedInterrupt106
2d65dee60000009b:	805420fe nt!KiUnexpectedInterrupt107
2d65dee60000009c:	80542108 nt!KiUnexpectedInterrupt108
2d65dee60000009d:	80542112 nt!KiUnexpectedInterrupt109
2d65dee60000009e:	8054211c nt!KiUnexpectedInterrupt110
2d65dee60000009f:	80542126 nt!KiUnexpectedInterrupt111
2d65dee6000000a0:	80542130 nt!KiUnexpectedInterrupt112
2d65dee6000000a1:	8054213a nt!KiUnexpectedInterrupt113
2d65dee6000000a2:	80542144 nt!KiUnexpectedInterrupt114
2d65dee6000000a3:	81f306ec i8042prt!I8042MouseInterruptService (KINTERRUPT 81f306b0)
2d65dee6000000a4:	80542158 nt!KiUnexpectedInterrupt116
2d65dee6000000a5:	80542162 nt!KiUnexpectedInterrupt117
2d65dee6000000a6:	8054216c nt!KiUnexpectedInterrupt118
2d65dee6000000a7:	80542176 nt!KiUnexpectedInterrupt119
2d65dee6000000a8:	80542180 nt!KiUnexpectedInterrupt120
2d65dee6000000a9:	8054218a nt!KiUnexpectedInterrupt121
2d65dee6000000aa:	80542194 nt!KiUnexpectedInterrupt122
2d65dee6000000ab:	8054219e nt!KiUnexpectedInterrupt123
2d65dee6000000ac:	805421a8 nt!KiUnexpectedInterrupt124
2d65dee6000000ad:	805421b2 nt!KiUnexpectedInterrupt125
2d65dee6000000ae:	805421bc nt!KiUnexpectedInterrupt126
2d65dee6000000af:	805421c6 nt!KiUnexpectedInterrupt127
2d65dee6000000b0:	805421d0 nt!KiUnexpectedInterrupt128
2d65dee6000000b1:	821522ac ACPI!ACPIInterruptServiceRoutine (KINTERRUPT 82152270)
2d65dee6000000b2:	805421e4 nt!KiUnexpectedInterrupt130
2d65dee6000000b3:	805421ee nt!KiUnexpectedInterrupt131
2d65dee6000000b4:	8201b2ac NDIS!ndisMIsr (KINTERRUPT 8201b270)
2d65dee6000000b5:	80542202 nt!KiUnexpectedInterrupt133
2d65dee6000000b6:	8054220c nt!KiUnexpectedInterrupt134
2d65dee6000000b7:	80542216 nt!KiUnexpectedInterrupt135
2d65dee6000000b8:	80542220 nt!KiUnexpectedInterrupt136
2d65dee6000000b9:	8054222a nt!KiUnexpectedInterrupt137
2d65dee6000000ba:	80542234 nt!KiUnexpectedInterrupt138
2d65dee6000000bb:	8054223e nt!KiUnexpectedInterrupt139
2d65dee6000000bc:	80542248 nt!KiUnexpectedInterrupt140
2d65dee6000000bd:	80542252 nt!KiUnexpectedInterrupt141
2d65dee6000000be:	8054225c nt!KiUnexpectedInterrupt142
2d65dee6000000bf:	80542266 nt!KiUnexpectedInterrupt143
2d65dee6000000c0:	80542270 nt!KiUnexpectedInterrupt144
2d65dee6000000c1:	806e7ac0 hal!HalpBroadcastCallService
2d65dee6000000c2:	80542284 nt!KiUnexpectedInterrupt146
2d65dee6000000c3:	8054228e nt!KiUnexpectedInterrupt147
2d65dee6000000c4:	80542298 nt!KiUnexpectedInterrupt148
2d65dee6000000c5:	805422a2 nt!KiUnexpectedInterrupt149
2d65dee6000000c6:	805422ac nt!KiUnexpectedInterrupt150
2d65dee6000000c7:	805422b6 nt!KiUnexpectedInterrupt151
2d65dee6000000c8:	805422c0 nt!KiUnexpectedInterrupt152
2d65dee6000000c9:	805422ca nt!KiUnexpectedInterrupt153
2d65dee6000000ca:	805422d4 nt!KiUnexpectedInterrupt154
2d65dee6000000cb:	805422de nt!KiUnexpectedInterrupt155
2d65dee6000000cc:	805422e8 nt!KiUnexpectedInterrupt156
2d65dee6000000cd:	805422f2 nt!KiUnexpectedInterrupt157
2d65dee6000000ce:	805422fc nt!KiUnexpectedInterrupt158
2d65dee6000000cf:	80542306 nt!KiUnexpectedInterrupt159
2d65dee6000000d0:	80542310 nt!KiUnexpectedInterrupt160
2d65dee6000000d1:	806e72a0 hal!HalpClockInterruptPn
2d65dee6000000d2:	80542324 nt!KiUnexpectedInterrupt162
2d65dee6000000d3:	8054232e nt!KiUnexpectedInterrupt163
2d65dee6000000d4:	80542338 nt!KiUnexpectedInterrupt164
2d65dee6000000d5:	80542342 nt!KiUnexpectedInterrupt165
2d65dee6000000d6:	8054234c nt!KiUnexpectedInterrupt166
2d65dee6000000d7:	80542356 nt!KiUnexpectedInterrupt167
2d65dee6000000d8:	80542360 nt!KiUnexpectedInterrupt168
2d65dee6000000d9:	8054236a nt!KiUnexpectedInterrupt169
2d65dee6000000da:	80542374 nt!KiUnexpectedInterrupt170
2d65dee6000000db:	8054237e nt!KiUnexpectedInterrupt171
2d65dee6000000dc:	80542388 nt!KiUnexpectedInterrupt172
2d65dee6000000dd:	80542392 nt!KiUnexpectedInterrupt173
2d65dee6000000de:	8054239c nt!KiUnexpectedInterrupt174
2d65dee6000000df:	805423a6 nt!KiUnexpectedInterrupt175
2d65dee6000000e0:	805423b0 nt!KiUnexpectedInterrupt176
2d65dee6000000e1:	806e8048 hal!HalpIpiHandler
2d65dee6000000e2:	805423c4 nt!KiUnexpectedInterrupt178
2d65dee6000000e3:	806e7dac hal!HalpLocalApicErrorService
2d65dee6000000e4:	805423d8 nt!KiUnexpectedInterrupt180
2d65dee6000000e5:	805423e2 nt!KiUnexpectedInterrupt181
2d65dee6000000e6:	805423ec nt!KiUnexpectedInterrupt182
2d65dee6000000e7:	805423f6 nt!KiUnexpectedInterrupt183
2d65dee6000000e8:	80542400 nt!KiUnexpectedInterrupt184
2d65dee6000000e9:	8054240a nt!KiUnexpectedInterrupt185
2d65dee6000000ea:	80542414 nt!KiUnexpectedInterrupt186
2d65dee6000000eb:	8054241e nt!KiUnexpectedInterrupt187
2d65dee6000000ec:	80542428 nt!KiUnexpectedInterrupt188
2d65dee6000000ed:	80542432 nt!KiUnexpectedInterrupt189
2d65dee6000000ee:	80542439 nt!KiUnexpectedInterrupt190
2d65dee6000000ef:	80542440 nt!KiUnexpectedInterrupt191
2d65dee6000000f0:	80542447 nt!KiUnexpectedInterrupt192
2d65dee6000000f1:	8054244e nt!KiUnexpectedInterrupt193
2d65dee6000000f2:	80542455 nt!KiUnexpectedInterrupt194
2d65dee6000000f3:	8054245c nt!KiUnexpectedInterrupt195
2d65dee6000000f4:	80542463 nt!KiUnexpectedInterrupt196
2d65dee6000000f5:	8054246a nt!KiUnexpectedInterrupt197
2d65dee6000000f6:	80542471 nt!KiUnexpectedInterrupt198
2d65dee6000000f7:	80542478 nt!KiUnexpectedInterrupt199
2d65dee6000000f8:	8054247f nt!KiUnexpectedInterrupt200
2d65dee6000000f9:	80542486 nt!KiUnexpectedInterrupt201
2d65dee6000000fa:	8054248d nt!KiUnexpectedInterrupt202
2d65dee6000000fb:	80542494 nt!KiUnexpectedInterrupt203
2d65dee6000000fc:	8054249b nt!KiUnexpectedInterrupt204
2d65dee6000000fd:	806e85a8 hal!HalpProfileInterrupt
2d65dee6000000fe:	806e8748 hal!HalpPerfInterrupt
2d65dee6000000ff:	805424b0 nt!KiUnexpectedInterrupt207

kd> r idtr
idtr=8003f400
kd> !idt 8003f400

Dumping IDT: 8003f400

fbf4ec7d8003f400:	Task Selector = 0x6F4C
kd> dt _KIDTENTRY
nt!_KIDTENTRY
   +0x000 Offset           : Uint2B
   +0x002 Selector         : Uint2B
   +0x004 Access           : Uint2B
   +0x006 ExtendedOffset   : Uint2B
kd> dt _X86_DESCRIPTOR
Symbol _X86_DESCRIPTOR not found.
kd> dt _DESCRIPTOR ע�⣺64λ��û������ṹ��
nt!_DESCRIPTOR
   +0x000 Pad              : Uint2B
   +0x002 Limit            : Uint2B
   +0x004 Base             : Uint4B
0: kd> dt nt!_KINTERRUPT 8208e398
   +0x000 Type             : 0n22
   +0x002 Size             : 0n484
   +0x004 InterruptListEntry : _LIST_ENTRY [ 0x8208e39c - 0x8208e39c ]
   +0x00c ServiceRoutine   : 0xba63e67e     unsigned char  atapi!IdePortInterrupt+0
   +0x010 ServiceContext   : 0x81fa4030 Void
   +0x014 SpinLock         : 0
   +0x018 TickCount        : 0xffffffff
   +0x01c ActualLock       : 0x8208e5fc  -> 0
   +0x020 DispatchAddress  : 0x80546780     void  nt!KiInterruptDispatch+0
   +0x024 Vector           : 0x162
   +0x028 Irql             : 0x5 ''
   +0x029 SynchronizeIrql  : 0x5 ''
   +0x02a FloatingSave     : 0 ''
   +0x02b Connected        : 0x1 ''
   +0x02c Number           : 0 ''
   +0x02d ShareVector      : 0 ''
   +0x030 Mode             : 1 ( Latched )
   +0x034 ServiceCount     : 0
   +0x038 DispatchCount    : 0xffffffff
   +0x03c DispatchCode     : [106] 0x56535554

1: kd> dt _AMD64_DESCRIPTOR ע�⣺���л�����64λϵͳ��
test!_AMD64_DESCRIPTOR
   +0x000 Pad              : [3] Uint2B
   +0x006 Limit            : Uint2B
   +0x008 Base             : Uint8B
1: kd> dt _KIDTENTRY64 ע�⣺���л�����64λϵͳ��
nt!_KIDTENTRY64
   +0x000 OffsetLow        : Uint2B
   +0x002 Selector         : Uint2B
   +0x004 IstIndex         : Pos 0, 3 Bits
   +0x004 Reserved0        : Pos 3, 5 Bits
   +0x004 Type             : Pos 8, 5 Bits
   +0x004 Dpl              : Pos 13, 2 Bits
   +0x004 Present          : Pos 15, 1 Bit
   +0x006 OffsetMiddle     : Uint2B
   +0x008 OffsetHigh       : Uint4B
   +0x00c Reserved1        : Uint4B
   +0x000 Alignment        : Uint8B
0: kd> r idtl
idtl=000007ff
*/


//////////////////////////////////////////////////////////////////////////////////////////////////
