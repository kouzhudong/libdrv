#include "pch.h"


FORCEINLINE
__drv_allocatesMem(Mem)
_When_((PoolType & PagedPool) != 0, _IRQL_requires_max_(APC_LEVEL))
_When_((PoolType & PagedPool) == 0, _IRQL_requires_max_(DISPATCH_LEVEL))
_Post_writable_byte_size_(NumberOfBytes)
PVOID NTAPI AllocatePoolZero(
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
)
/*
ÐÞ¸Ä×Ô£º\Windows Kits\10\Include\10.0.22621.0\km\wdm.hµÄExAllocatePoolZero
*/
{
    PVOID Allocation;

    Allocation = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
    if (Allocation) {
        RtlZeroMemory(Allocation, NumberOfBytes);
    }

    return Allocation;
}
