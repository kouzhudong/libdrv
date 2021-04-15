#include "TEB.h"


//////////////////////////////////////////////////////////////////////////////////////////////////
//摘自：\Windows Kits\10\Include\10.0.19041.0\km\ntddk.h
//从这里你可以看到NT_TIB，NT_TIB32，NT_TIB64的定义。


#if defined(_M_AMD64) && !defined(__midl)

__forceinline
struct _TEB * NTAPI NtCurrentTeb(VOID)
{
    return (struct _TEB *)__readgsqword(FIELD_OFFSET(NT_TIB, Self));
}

__forceinline
PVOID
GetCurrentFiber(
    VOID
)

{

    return (PVOID)__readgsqword(FIELD_OFFSET(NT_TIB, FiberData));
}

__forceinline
PVOID
GetFiberData(
    VOID
)

{

    return *(PVOID *)GetCurrentFiber();
}

#endif // _M_AMD64 && !defined(__midl)


#if defined(_M_ARM) && !defined(__midl) && !defined(_M_CEE_PURE)

__forceinline
struct _TEB *
    NtCurrentTeb(
        VOID
    )
{
    return (struct _TEB *)(ULONG_PTR)_MoveFromCoprocessor(CP15_TPIDRURW);
}

__forceinline
PVOID
GetCurrentFiber(
    VOID
)
{
    return ((PNT_TIB)(ULONG_PTR)_MoveFromCoprocessor(CP15_TPIDRURW))->FiberData;
}

__forceinline
PVOID
GetFiberData(
    VOID
)

{
    return *(PVOID *)GetCurrentFiber();
}

#endif // _M_ARM && !defined(__midl) && !defined(_M_CEE_PURE)


#if defined(_M_ARM64) && !defined(__midl) && !defined(_M_CEE_PURE)

__forceinline
struct _TEB *
    NtCurrentTeb(
        VOID
    )
{
    return (struct _TEB *)__getReg(18);
}

__forceinline
PVOID
GetCurrentFiber(
    VOID
)
{
    return ((PNT_TIB)__getReg(18))->FiberData;
}

__forceinline
PVOID
GetFiberData(
    VOID
)

{
    return *(PVOID *)GetCurrentFiber();
}

#endif // _M_ARM64 && !defined(__midl) && !defined(_M_CEE_PURE)


#if defined(_M_IX86) && !defined(MIDL_PASS)

#define PcTeb 0x18

#if (_MSC_FULL_VER >= 13012035)

__inline 
struct _TEB * NTAPI NtCurrentTeb(VOID) { return (struct _TEB *)(ULONG_PTR)__readfsdword(PcTeb); }

#else

#if _MSC_VER >= 1200
#pragma warning(push)
#endif

#pragma warning (disable:4035)        // disable 4035 (function must return something)

__inline
struct _TEB * NTAPI NtCurrentTeb(VOID) { __asm mov eax, fs: [PcTeb] }

#if _MSC_VER >= 1200
#pragma warning(pop)
#else
#pragma warning (default:4035)        // reenable it
#endif

#endif

#endif // defined(_M_IX86) && !defined(MIDL_PASS)


//////////////////////////////////////////////////////////////////////////////////////////////////
