#include "cpp.h"


#pragma warning(disable : 5043) //异常规范与前面的声明不匹配


_IRQL_requires_max_(DISPATCH_LEVEL)
void * __cdecl operator new(size_t size, void * p) noexcept
// ============== 定位 new (Placement New) (必须存在) ==============
// 定位 new 必须保持原样，它不分配内存，只返回指针
{
    UNREFERENCED_PARAMETER(size);
    return p;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void * p, void * q) noexcept
//定位 delete (当定位 new 的构造函数失败时调用)
{
    UNREFERENCED_PARAMETER(p);
    UNREFERENCED_PARAMETER(q);
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void * __cdecl operator new(_In_ size_t size) noexcept
{
    if (size == 0) {
        return nullptr;
    }

    const auto p = ExAllocatePoolWithTag(NonPagedPool, size, TAG);
    if (p) { RtlZeroMemory(p, size); }
    return p;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(_In_ void * p) noexcept
{
    if (p) {
        ExFreePoolWithTag(p, TAG);
    }
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(_In_ void * p, _In_ SIZE_T size) noexcept
{
    UNREFERENCED_PARAMETER(size);

    if (p) {
        //ExFreePoolWithTag(p, TAG);
        operator delete(p);
    }
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void * __cdecl operator new[](_In_ size_t size) noexcept
{
    if (size == 0) {
        return nullptr;
    }

    //const auto p = ExAllocatePoolWithTag(NonPagedPool, size, TAG);
    const auto p = operator new(size);
    if (p) {
        RtlZeroMemory(p, size);
    }

    return p;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete[](_In_ void * p) noexcept
{
    if (p) {
        //ExFreePoolWithTag(p, TAG);
        operator delete(p);
    }
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete[](_In_ void * p, _In_ SIZE_T size) noexcept
{
    UNREFERENCED_PARAMETER(size);
    if (p) {
        //ExFreePoolWithTag(p, TAG);
        operator delete(p);
    }
}
