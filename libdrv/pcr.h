/*
文件名：KeGetPcr.c
功能：获取某个CPU的PCR/PRCB。

以前感觉eprocess/kprocess和_ethread/_kthread就很厉害了。
其实还有比他们更加底层的，这就是_kpcr和_kprcb。
更多的还有blos,PCI等硬件信息。

以前觉得这太底层，不敢触及。
其实这是必须接触，接触到有很多的好处。
本文没有用汇编语法实现的X86和X64的编程。其实也是变相的汇编，由编译器实现而已。
看来搞系统，不但知道系统的知识，还要知道编译环境的信息，会更好。

软件再智能，再高级也是借助于硬件实现的。
没用硬件，连空虚的灵魂都没有。

本文参考：WDK和MSDN。

made by correy
made at 2014.08.22
*/


/*
X86的验证：
0: kd> !pcr
KPCR for Processor 0 at ffdff000:
	Major 1 Minor 1
	NtTib.ExceptionList: f88f6578
		NtTib.StackBase: f88f6df0
	   NtTib.StackLimit: f88f4000
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

		  CurrentThread: 8234c8a0
			 NextThread: 00000000
			 IdleThread: 8055ce60

			  DpcQueue:
0: kd> !pcr 0
KPCR for Processor 0 at ffdff000:
	Major 1 Minor 1
	NtTib.ExceptionList: f88f6578
		NtTib.StackBase: f88f6df0
	   NtTib.StackLimit: f88f4000
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

		  CurrentThread: 8234c8a0
			 NextThread: 00000000
			 IdleThread: 8055ce60

			  DpcQueue:
0: kd> dt nt!_kpcr ffdff000
   +0x000 NtTib            : _NT_TIB
   +0x01c SelfPcr          : 0xffdff000 _KPCR
   +0x020 Prcb             : 0xffdff120 _KPRCB
   +0x024 Irql             : 0 ''
   +0x028 IRR              : 0
   +0x02c IrrActive        : 0
   +0x030 IDR              : 0xffffffff
   +0x034 KdVersionBlock   : 0x8054e2b8 Void
   +0x038 IDT              : 0x8003f400 _KIDTENTRY
   +0x03c GDT              : 0x8003f000 _KGDTENTRY
   +0x040 TSS              : 0x80042000 _KTSS
   +0x044 MajorVersion     : 1
   +0x046 MinorVersion     : 1
   +0x048 SetMember        : 1
   +0x04c StallScaleFactor : 0xd40
   +0x050 DebugActive      : 0 ''
   +0x051 Number           : 0 ''
   +0x052 Spare0           : 0 ''
   +0x053 SecondLevelCacheAssociativity : 0 ''
   +0x054 VdmAlert         : 0
   +0x058 KernelReserved   : [14] 0
   +0x090 SecondLevelCacheSize : 0
   +0x094 HalReserved      : [16] 0
   +0x0d4 InterruptMode    : 0      注意：从这里开始这里的在结构的定义里面是没有的。也就是说WINDBG命令显示的比结构定义的成员多四个。
   +0x0d8 Spare1           : 0 ''
   +0x0dc KernelReserved2  : [17] 0
   +0x120 PrcbData         : _KPRCB
0: kd> dt nt!_kpcr ffdff000 -b
   ...
   这命令太长就不显示了，有几千行。
0: kd> dt nt!_kprcb 0xffdff120
   +0x000 MinorVersion     : 1
   +0x002 MajorVersion     : 1
   +0x004 CurrentThread    : 0x8234c8a0 _KTHREAD
   +0x008 NextThread       : (null)
   +0x00c IdleThread       : 0x8055ce60 _KTHREAD
   +0x010 Number           : 0 ''
   +0x011 Reserved         : 0 ''
   +0x012 BuildType        : 0
   +0x014 SetMember        : 1
   +0x018 CpuType          : 6 ''
   +0x019 CpuID            : 1 ''
   +0x01a CpuStep          : 0x3a09
   +0x01c ProcessorState   : _KPROCESSOR_STATE
   +0x33c KernelReserved   : [16] 0
   +0x37c HalReserved      : [16] 0
   +0x3bc PrcbPad0         : [92]  ""
   +0x418 LockQueue        : [16] _KSPIN_LOCK_QUEUE
   +0x498 PrcbPad1         : [8]  ""
   +0x4a0 NpxThread        : (null)
   +0x4a4 InterruptCount   : 0x87e0
   +0x4a8 KernelTime       : 0x50b7
   +0x4ac UserTime         : 0x89
   +0x4b0 DpcTime          : 0x47
   +0x4b4 DebugDpcTime     : 0
   +0x4b8 InterruptTime    : 0x33b
   +0x4bc AdjustDpcThreshold : 0x14
   +0x4c0 PageColor        : 0x14a14
   +0x4c4 SkipTick         : 1
   +0x4c8 MultiThreadSetBusy : 0x1 ''
   +0x4c9 Spare2           : [3]  ""
   +0x4cc ParentNode       : 0x8055d560 _KNODE
   +0x4d0 MultiThreadProcessorSet : 3
   +0x4d4 MultiThreadSetMaster : 0xffdff120 _KPRCB
   +0x4d8 ThreadStartCount : [2] 0
   +0x4e0 CcFastReadNoWait : 0
   +0x4e4 CcFastReadWait   : 0x27f
   +0x4e8 CcFastReadNotPossible : 0
   +0x4ec CcCopyReadNoWait : 6
   +0x4f0 CcCopyReadWait   : 0x344
   +0x4f4 CcCopyReadNoWaitMiss : 1
   +0x4f8 KeAlignmentFixupCount : 0
   +0x4fc KeContextSwitches : 0x2c332
   +0x500 KeDcacheFlushCount : 0
   +0x504 KeExceptionDispatchCount : 0xc4
   +0x508 KeFirstLevelTbFills : 0
   +0x50c KeFloatingEmulationCount : 0
   +0x510 KeIcacheFlushCount : 0
   +0x514 KeSecondLevelTbFills : 0
   +0x518 KeSystemCalls    : 0xd1c9d
   +0x51c SpareCounter0    : [1] 0
   +0x520 PPLookasideList  : [16] _PP_LOOKASIDE_LIST
   +0x5a0 PPNPagedLookasideList : [32] _PP_LOOKASIDE_LIST
   +0x6a0 PPPagedLookasideList : [32] _PP_LOOKASIDE_LIST
   +0x7a0 PacketBarrier    : 0
   +0x7a4 ReverseStall     : 0xce
   +0x7a8 IpiFrame         : 0xf871ea9c Void
   +0x7ac PrcbPad2         : [52]  ""
   +0x7e0 CurrentPacket    : [3] 0x00000001 Void
   +0x7ec TargetSet        : 0
   +0x7f0 WorkerRoutine    : 0x804fc26a     void  nt!KiFlushTargetMultipleTb+0
   +0x7f4 IpiFrozen        : 0x24
   +0x7f8 PrcbPad3         : [40]  ""
   +0x820 RequestSummary   : 0
   +0x824 SignalDone       : (null)
   +0x828 PrcbPad4         : [56]  ""
   +0x860 DpcListHead      : _LIST_ENTRY [ 0xffdff980 - 0xffdff980 ]
   +0x868 DpcStack         : 0xf88c7000 Void
   +0x86c DpcCount         : 0x29e6
   +0x870 DpcQueueDepth    : 0
   +0x874 DpcRoutineActive : 0
   +0x878 DpcInterruptRequested : 0
   +0x87c DpcLastCount     : 0x29e6
   +0x880 DpcRequestRate   : 0
   +0x884 MaximumDpcQueueDepth : 1
   +0x888 MinimumDpcRate   : 3
   +0x88c QuantumEnd       : 0
   +0x890 PrcbPad5         : [16]  ""
   +0x8a0 DpcLock          : 0
   +0x8a4 PrcbPad6         : [28]  ""
   +0x8c0 CallDpc          : _KDPC
   +0x8e0 ChainedInterruptList : (null)
   +0x8e4 LookasideIrpFloat : 0n768
   +0x8e8 SpareFields0     : [6] 0
   +0x900 VendorString     : [13]  "GenuineIntel"
   +0x90d InitialApicId    : 0 ''
   +0x90e LogicalProcessorsPerPhysicalProcessor : 0x2 ''
   +0x910 MHz              : 0xd40
   +0x914 FeatureBits      : 0xa0033fff
   +0x918 UpdateSignature  : _LARGE_INTEGER 0x00000017`00000000
   +0x920 NpxSaveArea      : _FX_SAVE_AREA
   +0xb30 PowerState       : _PROCESSOR_POWER_STATE
0: kd> dt nt!_kpcr poi(pkpcr) 这是编程获取的，可以和前面的对比。
   +0x000 NtTib            : _NT_TIB
   +0x01c SelfPcr          : 0xffdff000 _KPCR
   +0x020 Prcb             : 0xffdff120 _KPRCB
   +0x024 Irql             : 0 ''
   +0x028 IRR              : 0
   +0x02c IrrActive        : 0
   +0x030 IDR              : 0xffffffff
   +0x034 KdVersionBlock   : 0x8054e2b8 Void
   +0x038 IDT              : 0x8003f400 _KIDTENTRY
   +0x03c GDT              : 0x8003f000 _KGDTENTRY
   +0x040 TSS              : 0x80042000 _KTSS
   +0x044 MajorVersion     : 1
   +0x046 MinorVersion     : 1
   +0x048 SetMember        : 1
   +0x04c StallScaleFactor : 0xd40
   +0x050 DebugActive      : 0 ''
   +0x051 Number           : 0 ''
   +0x052 Spare0           : 0 ''
   +0x053 SecondLevelCacheAssociativity : 0 ''
   +0x054 VdmAlert         : 0
   +0x058 KernelReserved   : [14] 0
   +0x090 SecondLevelCacheSize : 0
   +0x094 HalReserved      : [16] 0
   +0x0d4 InterruptMode    : 0
   +0x0d8 Spare1           : 0 ''
   +0x0dc KernelReserved2  : [17] 0
   +0x120 PrcbData         : _KPRCB
*/


/*
X64的验证：
0: kd> !pcr
KPCR for Processor 0 at fffff800019f9d00:
	Major 1 Minor 1
	NtTib.ExceptionList: fffff80001753000
		NtTib.StackBase: fffff80001754080
	   NtTib.StackLimit: 000000000008e2e8
	 NtTib.SubSystemTib: fffff800019f9d00
		  NtTib.Version: 00000000019f9e80
	  NtTib.UserPointer: fffff800019fa4f0
		  NtTib.SelfTib: 000007fffff9e000

				SelfPcr: 0000000000000000
				   Prcb: fffff800019f9e80
				   Irql: 0000000000000000
					IRR: 0000000000000000
					IDR: 0000000000000000
		  InterruptMode: 0000000000000000
					IDT: 0000000000000000
					GDT: 0000000000000000
					TSS: 0000000000000000

		  CurrentThread: fffffa8018df6680
			 NextThread: 0000000000000000
			 IdleThread: fffff80001a07cc0

			  DpcQueue:
0: kd> !pcr 0
KPCR for Processor 0 at fffff800019f9d00:
	Major 1 Minor 1
	NtTib.ExceptionList: fffff80001753000
		NtTib.StackBase: fffff80001754080
	   NtTib.StackLimit: 000000000008e2e8
	 NtTib.SubSystemTib: fffff800019f9d00
		  NtTib.Version: 00000000019f9e80
	  NtTib.UserPointer: fffff800019fa4f0
		  NtTib.SelfTib: 000007fffff9e000

				SelfPcr: 0000000000000000
				   Prcb: fffff800019f9e80
				   Irql: 0000000000000000
					IRR: 0000000000000000
					IDR: 0000000000000000
		  InterruptMode: 0000000000000000
					IDT: 0000000000000000
					GDT: 0000000000000000
					TSS: 0000000000000000

		  CurrentThread: fffffa8018df6680
			 NextThread: 0000000000000000
			 IdleThread: fffff80001a07cc0

			  DpcQueue:
0: kd> dt nt!_kpcr fffff800019f9d00
   +0x000 NtTib            : _NT_TIB
   +0x000 GdtBase          : 0xfffff800`01753000 _KGDTENTRY64
   +0x008 TssBase          : 0xfffff800`01754080 _KTSS64
   +0x010 UserRsp          : 0x8e2e8
   +0x018 Self             : 0xfffff800`019f9d00 _KPCR
   +0x020 CurrentPrcb      : 0xfffff800`019f9e80 _KPRCB
   +0x028 LockArray        : 0xfffff800`019fa4f0 _KSPIN_LOCK_QUEUE
   +0x030 Used_Self        : 0x000007ff`fff9e000 Void
   +0x038 IdtBase          : 0xfffff800`01753080 _KIDTENTRY64
   +0x040 Unused           : [2] 0
   +0x050 Irql             : 0 ''
   +0x051 SecondLevelCacheAssociativity : 0xc ''
   +0x052 ObsoleteNumber   : 0 ''
   +0x053 Fill0            : 0 ''
   +0x054 Unused0          : [3] 0
   +0x060 MajorVersion     : 1
   +0x062 MinorVersion     : 1
   +0x064 StallScaleFactor : 0xd40
   +0x068 Unused1          : [3] (null)
   +0x080 KernelReserved   : [15] 0
   +0x0bc SecondLevelCacheSize : 0x300000
   +0x0c0 HalReserved      : [16] 0xca332730
   +0x100 Unused2          : 0
   +0x108 KdVersionBlock   : (null)
   +0x110 Unused3          : (null)
   +0x118 PcrAlign1        : [24] 0
   +0x180 Prcb             : _KPRCB 注意：从这里开始这里的在结构的定义里面是没有的。也就是说WINDBG命令显示的比结构定义的成员多四个。
0: kd> dt nt!_kprcb fffff800019f9e80
   +0x000 MxCsr            : 0x1f80
   +0x004 LegacyNumber     : 0 ''
   +0x005 ReservedMustBeZero : 0 ''
   +0x006 InterruptRequest : 0 ''
   +0x007 IdleHalt         : 0 ''
   +0x008 CurrentThread    : 0xfffffa80`18df6680 _KTHREAD
   +0x010 NextThread       : (null)
   +0x018 IdleThread       : 0xfffff800`01a07cc0 _KTHREAD
   +0x020 NestingLevel     : 0 ''
   +0x021 PrcbPad00        : [3]  ""
   +0x024 Number           : 0
   +0x028 RspBase          : 0xfffff880`0231dc70
   +0x030 PrcbLock         : 0
   +0x038 PrcbPad01        : 0
   +0x040 ProcessorState   : _KPROCESSOR_STATE
   +0x5f0 CpuType          : 6 ''
   +0x5f1 CpuID            : 1 ''
   +0x5f2 CpuStep          : 0x3a09
   +0x5f2 CpuStepping      : 0x9 ''
   +0x5f3 CpuModel         : 0x3a ':'
   +0x5f4 MHz              : 0xd40
   +0x5f8 HalReserved      : [8] 0
   +0x638 MinorVersion     : 1
   +0x63a MajorVersion     : 1
   +0x63c BuildType        : 0 ''
   +0x63d CpuVendor        : 0x2 ''
   +0x63e CoresPerPhysicalProcessor : 0x2 ''
   +0x63f LogicalProcessorsPerCore : 0x1 ''
   +0x640 ApicMask         : 0xfffffffe
   +0x644 CFlushSize       : 0x40
   +0x648 AcpiReserved     : (null)
   +0x650 InitialApicId    : 0
   +0x654 Stride           : 2
   +0x658 Group            : 0
   +0x660 GroupSetMember   : 1
   +0x668 GroupIndex       : 0 ''
   +0x670 LockQueue        : [17] _KSPIN_LOCK_QUEUE
   +0x780 PPLookasideList  : [16] _PP_LOOKASIDE_LIST
   +0x880 PPNPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
   +0x1480 PPPagedLookasideList : [32] _GENERAL_LOOKASIDE_POOL
   +0x2080 PacketBarrier    : 0n0
   +0x2088 DeferredReadyListHead : _SINGLE_LIST_ENTRY
   +0x2090 MmPageFaultCount : 0n152708
   +0x2094 MmCopyOnWriteCount : 0n3321
   +0x2098 MmTransitionCount : 0n64413
   +0x209c MmDemandZeroCount : 0n64284
   +0x20a0 MmPageReadCount  : 0n46114
   +0x20a4 MmPageReadIoCount : 0n8302
   +0x20a8 MmDirtyPagesWriteCount : 0n0
   +0x20ac MmDirtyWriteIoCount : 0n0
   +0x20b0 MmMappedPagesWriteCount : 0n1
   +0x20b4 MmMappedWriteIoCount : 0n1
   +0x20b8 KeSystemCalls    : 0x1fd8c5
   +0x20bc KeContextSwitches : 0x219d2
   +0x20c0 CcFastReadNoWait : 0
   +0x20c4 CcFastReadWait   : 0x1648
   +0x20c8 CcFastReadNotPossible : 0
   +0x20cc CcCopyReadNoWait : 0
   +0x20d0 CcCopyReadWait   : 0x1865
   +0x20d4 CcCopyReadNoWaitMiss : 0
   +0x20d8 LookasideIrpFloat : 0n2147483647
   +0x20dc IoReadOperationCount : 0n7516
   +0x20e0 IoWriteOperationCount : 0n1741
   +0x20e4 IoOtherOperationCount : 0n70676
   +0x20e8 IoReadTransferCount : _LARGE_INTEGER 0x51033c0
   +0x20f0 IoWriteTransferCount : _LARGE_INTEGER 0x1786f65
   +0x20f8 IoOtherTransferCount : _LARGE_INTEGER 0x1feec4
   +0x2100 TargetCount      : 0n0
   +0x2104 IpiFrozen        : 0x24
   +0x2180 DpcData          : [2] _KDPC_DATA
   +0x21c0 DpcStack         : 0xfffff800`01760fb0 Void
   +0x21c8 MaximumDpcQueueDepth : 0n4
   +0x21cc DpcRequestRate   : 0
   +0x21d0 MinimumDpcRate   : 3
   +0x21d4 DpcLastCount     : 0x55dc
   +0x21d8 ThreadDpcEnable  : 0x1 ''
   +0x21d9 QuantumEnd       : 0 ''
   +0x21da DpcRoutineActive : 0 ''
   +0x21db IdleSchedule     : 0 ''
   +0x21dc DpcRequestSummary : 0n0
   +0x21dc DpcRequestSlot   : [2] 0n0
   +0x21dc NormalDpcState   : 0n0
   +0x21de DpcThreadActive  : 0y0
   +0x21de ThreadDpcState   : 0n0
   +0x21e0 TimerHand        : 0x2eac
   +0x21e4 MasterOffset     : 0n8675
   +0x21e8 LastTick         : 0x2eac
   +0x21ec UnusedPad        : 0
   +0x21f0 PrcbPad50        : [2] 0
   +0x2200 TimerTable       : _KTIMER_TABLE
   +0x4400 DpcGate          : _KGATE
   +0x4418 PrcbPad52        : (null)
   +0x4420 CallDpc          : _KDPC
   +0x4460 ClockKeepAlive   : 0n1
   +0x4464 ClockCheckSlot   : 0x1 ''
   +0x4465 ClockPollCycle   : 0x53 'S'
   +0x4466 NmiActive        : 0
   +0x4468 DpcWatchdogPeriod : 0n1924
   +0x446c DpcWatchdogCount : 0n1741
   +0x4470 TickOffset       : 0x23f7e
   +0x4478 KeSpinLockOrdering : 0n0
   +0x447c PrcbPad70        : 0
   +0x4480 WaitListHead     : _LIST_ENTRY [ 0xfffffa80`1a996c00 - 0xfffffa80`18df70e0 ]
   +0x4490 WaitLock         : 0
   +0x4498 ReadySummary     : 0x1500
   +0x449c QueueIndex       : 1
   +0x44a0 TimerExpirationDpc : _KDPC
   +0x44e0 PrcbPad72        : [4] 0
   +0x4500 DispatcherReadyListHead : [32] _LIST_ENTRY [ 0xfffff800`019fe380 - 0xfffff800`019fe380 ]
   +0x4700 InterruptCount   : 0x11edc
   +0x4704 KernelTime       : 0x2d4b
   +0x4708 UserTime         : 0x161
   +0x470c DpcTime          : 0x55
   +0x4710 InterruptTime    : 0x213
   +0x4714 AdjustDpcThreshold : 0xc
   +0x4718 DebuggerSavedIRQL : 0 ''
   +0x4719 PrcbPad80        : [7]  ""
   +0x4720 DpcTimeCount     : 0
   +0x4724 DpcTimeLimit     : 0x282
   +0x4728 PeriodicCount    : 0
   +0x472c PeriodicBias     : 0
   +0x4730 AvailableTime    : 0x73
   +0x4734 KeExceptionDispatchCount : 0x58c0
   +0x4738 ParentNode       : 0xfffff800`01a07c00 _KNODE
   +0x4740 StartCycles      : 0x00000096`d20559b7
   +0x4748 PrcbPad82        : [3] 0
   +0x4760 MmSpinLockOrdering : 0n0
   +0x4764 PageColor        : 0x3abb
   +0x4768 NodeColor        : 0
   +0x476c NodeShiftedColor : 0
   +0x4770 SecondaryColorMask : 0x3f
   +0x4774 PrcbPad83        : 0
   +0x4778 CycleTime        : 0x00000015`c0c9fe04
   +0x4780 CcFastMdlReadNoWait : 0
   +0x4784 CcFastMdlReadWait : 0
   +0x4788 CcFastMdlReadNotPossible : 0
   +0x478c CcMapDataNoWait  : 0
   +0x4790 CcMapDataWait    : 0x5ce8
   +0x4794 CcPinMappedDataCount : 0x573
   +0x4798 CcPinReadNoWait  : 0
   +0x479c CcPinReadWait    : 0x160
   +0x47a0 CcMdlReadNoWait  : 0
   +0x47a4 CcMdlReadWait    : 0
   +0x47a8 CcLazyWriteHotSpots : 0x18
   +0x47ac CcLazyWriteIos   : 0xdb
   +0x47b0 CcLazyWritePages : 0x1cb3
   +0x47b4 CcDataFlushes    : 0x1e3
   +0x47b8 CcDataPages      : 0x1ad7
   +0x47bc CcLostDelayedWrites : 0
   +0x47c0 CcFastReadResourceMiss : 0
   +0x47c4 CcCopyReadWaitMiss : 0xc4b
   +0x47c8 CcFastMdlReadResourceMiss : 0
   +0x47cc CcMapDataNoWaitMiss : 0
   +0x47d0 CcMapDataWaitMiss : 0x63e
   +0x47d4 CcPinReadNoWaitMiss : 0
   +0x47d8 CcPinReadWaitMiss : 0x1a
   +0x47dc CcMdlReadNoWaitMiss : 0
   +0x47e0 CcMdlReadWaitMiss : 0
   +0x47e4 CcReadAheadIos   : 0x1ea3
   +0x47e8 MmCacheTransitionCount : 0n0
   +0x47ec MmCacheReadCount : 0n0
   +0x47f0 MmCacheIoCount   : 0n0
   +0x47f4 PrcbPad91        : [1] 0
   +0x47f8 RuntimeAccumulation : 0x6f1b1aaa
   +0x4800 PowerState       : _PROCESSOR_POWER_STATE
   +0x4900 PrcbPad92        : [16]  ""
   +0x4910 KeAlignmentFixupCount : 0
   +0x4918 DpcWatchdogDpc   : _KDPC
   +0x4958 DpcWatchdogTimer : _KTIMER
   +0x4998 Cache            : [5] _CACHE_DESCRIPTOR
   +0x49d4 CacheCount       : 4
   +0x49d8 CachedCommit     : 0x86
   +0x49dc CachedResidentAvailable : 0xf6
   +0x49e0 HyperPte         : 0xfffff880`00800006 Void
   +0x49e8 WheaInfo         : 0xfffffa80`18e31960 Void
   +0x49f0 EtwSupport       : 0xfffffa80`18e4c010 Void
   +0x4a00 InterruptObjectPool : _SLIST_HEADER
   +0x4a10 HypercallPageList : _SLIST_HEADER
   +0x4a20 HypercallPageVirtual : 0xfffff880`02d53000 Void
   +0x4a28 VirtualApicAssist : 0xfffff880`02d51000 Void
   +0x4a30 StatisticsPage   : 0xfffff880`02d52000  -> 0x00900001`00000002
   +0x4a38 RateControl      : (null)
   +0x4a40 CacheProcessorMask : [5] 3
   +0x4a68 PackageProcessorSet : _KAFFINITY_EX
   +0x4a90 CoreProcessorSet : 1
   +0x4a98 PebsIndexAddress : 0xfffff800`019fe918 Void
   +0x4aa0 PrcbPad93        : [12] 0
   +0x4b00 SpinLockAcquireCount : 0x5310d6
   +0x4b04 SpinLockContentionCount : 0xa1e
   +0x4b08 SpinLockSpinCount : 0x392b847a
   +0x4b0c IpiSendRequestBroadcastCount : 0x21e2
   +0x4b10 IpiSendRequestRoutineCount : 0x21f
   +0x4b14 IpiSendSoftwareInterruptCount : 0x5f77
   +0x4b18 ExInitializeResourceCount : 0x3497
   +0x4b1c ExReInitializeResourceCount : 0x47c
   +0x4b20 ExDeleteResourceCount : 0x2843
   +0x4b24 ExecutiveResourceAcquiresCount : 0x1861cb
   +0x4b28 ExecutiveResourceContentionsCount : 0x66e
   +0x4b2c ExecutiveResourceReleaseExclusiveCount : 0x367ca
   +0x4b30 ExecutiveResourceReleaseSharedCount : 0x14fa15
   +0x4b34 ExecutiveResourceConvertsCount : 0x305
   +0x4b38 ExAcqResExclusiveAttempts : 0x35d51
   +0x4b3c ExAcqResExclusiveAcquiresExclusive : 0x30a5d
   +0x4b40 ExAcqResExclusiveAcquiresExclusiveRecursive : 0x52d2
   +0x4b44 ExAcqResExclusiveWaits : 0x5b6
   +0x4b48 ExAcqResExclusiveNotAcquires : 0x22
   +0x4b4c ExAcqResSharedAttempts : 0x143531
   +0x4b50 ExAcqResSharedAcquiresExclusive : 0x1008
   +0x4b54 ExAcqResSharedAcquiresShared : 0x13f9db
   +0x4b58 ExAcqResSharedAcquiresSharedRecursive : 0x2b4b
   +0x4b5c ExAcqResSharedWaits : 0xb8
   +0x4b60 ExAcqResSharedNotAcquires : 3
   +0x4b64 ExAcqResSharedStarveExclusiveAttempts : 0xcf6f
   +0x4b68 ExAcqResSharedStarveExclusiveAcquiresExclusive : 1
   +0x4b6c ExAcqResSharedStarveExclusiveAcquiresShared : 0xceff
   +0x4b70 ExAcqResSharedStarveExclusiveAcquiresSharedRecursive : 0x6f
   +0x4b74 ExAcqResSharedStarveExclusiveWaits : 0
   +0x4b78 ExAcqResSharedStarveExclusiveNotAcquires : 0
   +0x4b7c ExAcqResSharedWaitForExclusiveAttempts : 0
   +0x4b80 ExAcqResSharedWaitForExclusiveAcquiresExclusive : 0
   +0x4b84 ExAcqResSharedWaitForExclusiveAcquiresShared : 0
   +0x4b88 ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive : 0
   +0x4b8c ExAcqResSharedWaitForExclusiveWaits : 0
   +0x4b90 ExAcqResSharedWaitForExclusiveNotAcquires : 0
   +0x4b94 ExSetResOwnerPointerExclusive : 0
   +0x4b98 ExSetResOwnerPointerSharedNew : 0x298
   +0x4b9c ExSetResOwnerPointerSharedOld : 0xba
   +0x4ba0 ExTryToAcqExclusiveAttempts : 0
   +0x4ba4 ExTryToAcqExclusiveAcquires : 0
   +0x4ba8 ExBoostExclusiveOwner : 0xe
   +0x4bac ExBoostSharedOwners : 0
   +0x4bb0 ExEtwSynchTrackingNotificationsCount : 0
   +0x4bb4 ExEtwSynchTrackingNotificationsAccountedCount : 0
   +0x4bb8 VendorString     : [13]  "GenuineIntel"
   +0x4bc5 PrcbPad10        : [3]  ""
   +0x4bc8 FeatureBits      : 0x21193dfe
   +0x4bd0 UpdateSignature  : _LARGE_INTEGER 0x00000017`00000000
   +0x4bd8 Context          : 0xfffff880`009c6340 _CONTEXT
   +0x4be0 ContextFlags     : 0x10004b
   +0x4be8 ExtendedState    : 0xfffff880`009c6000 _XSAVE_AREA
   +0x4c00 Mailbox          : (null)
   +0x4c80 RequestMailbox   : [1] _REQUEST_MAILBOX
0: kd> dt nt!_kpcr poi(pkpcr) 这是编程获取的，可以和前面的对比。
   +0x000 NtTib            : _NT_TIB
   +0x000 GdtBase          : 0xfffff800`01753000 _KGDTENTRY64
   +0x008 TssBase          : 0xfffff800`01754080 _KTSS64
   +0x010 UserRsp          : 0x8e2e8
   +0x018 Self             : 0xfffff800`019f9d00 _KPCR
   +0x020 CurrentPrcb      : 0xfffff800`019f9e80 _KPRCB
   +0x028 LockArray        : 0xfffff800`019fa4f0 _KSPIN_LOCK_QUEUE
   +0x030 Used_Self        : 0x000007ff`fff9e000 Void
   +0x038 IdtBase          : 0xfffff800`01753080 _KIDTENTRY64
   +0x040 Unused           : [2] 0
   +0x050 Irql             : 0 ''
   +0x051 SecondLevelCacheAssociativity : 0xc ''
   +0x052 ObsoleteNumber   : 0 ''
   +0x053 Fill0            : 0 ''
   +0x054 Unused0          : [3] 0
   +0x060 MajorVersion     : 1
   +0x062 MinorVersion     : 1
   +0x064 StallScaleFactor : 0xd40
   +0x068 Unused1          : [3] (null)
   +0x080 KernelReserved   : [15] 0
   +0x0bc SecondLevelCacheSize : 0x300000
   +0x0c0 HalReserved      : [16] 0xca332730
   +0x100 Unused2          : 0
   +0x108 KdVersionBlock   : (null)
   +0x110 Unused3          : (null)
   +0x118 PcrAlign1        : [24] 0
   +0x180 Prcb             : _KPRCB
*/


#pragma once


#include "pch.h"


//#include <wdbgexts.h> //这个属于应用层的文件。这里包含DBGKD_GET_VERSION64和DBGKD_DEBUG_DATA_HEADER64，KDDEBUGGER_DATA64等结构。


class pcr
{

};
