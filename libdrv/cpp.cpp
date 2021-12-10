#include "cpp.h"


_IRQL_requires_max_(DISPATCH_LEVEL)
void * __cdecl operator new(_In_ size_t size)
{
    if (size == 0) {
        return NULL;
    }

    const auto p = ExAllocatePoolWithTag(NonPagedPool, size, TAG);
    if (p) {
        RtlZeroMemory(p, size);
    }

    return p;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(_In_ void * p)
{
    if (p) {
        ExFreePoolWithTag(p, TAG);
    }
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(_In_ void * p, _In_ SIZE_T size)
{
    UNREFERENCED_PARAMETER(size);

    if (p) {
        ExFreePoolWithTag(p, TAG);
    }
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void * __cdecl operator new[](_In_ size_t size) {
    if (size == 0) {
        return NULL;
    }

    const auto p = ExAllocatePoolWithTag(NonPagedPool, size, TAG);
    if (p) {
        RtlZeroMemory(p, size);
    } 

    return p;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete[](_In_ void * p) {
    if (p) {
        ExFreePoolWithTag(p, TAG);
    }
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete[](_In_ void * p, _In_ SIZE_T size) {
    UNREFERENCED_PARAMETER(size);
    if (p) {
        ExFreePoolWithTag(p, TAG);
    }
}
