// 03-cpp-wdm-sys:WDK 原生 C++ 写的空 WDM 驱动。
// DriverEntry 中调用第 1 个工程(Rust kernel-lib)导出的 kernel_lib_add。

#include <ntddk.h>
#include "kernel_lib.h"

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" DRIVER_UNLOAD     DriverUnload;

extern "C" VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("cpp-wdm-sys: DriverUnload\n");
}

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // 调用 Rust 静态库导出的函数(其内部还会 DbgPrint 一行)。
    int sum = kernel_lib_add(2, 3);
    DbgPrint("cpp-wdm-sys: kernel_lib_add(2, 3) = %d\n", sum);

    // 取当前进程的 NT 设备全路径(DriverEntry 在 PASSIVE_LEVEL,满足要求)。
    // 先传 NULL 探所需长度,再按需用分页池分配重试——路径最长 32767 WCHAR(64KB),不能放栈。
    constexpr ULONG KLIB_PATH_TAG = 'PpLK';  // 池标记,DbgView/!poolused 显示为 "KLpp"
    ULONG    pid    = HandleToULong(PsGetCurrentProcessId());
    ULONG    needed = 0;
    NTSTATUS st     = kernel_lib_get_process_path(pid, NULL, 0, &needed);
    if (st == STATUS_BUFFER_TOO_SMALL) {
        ULONG cap = needed + 1;  // +1 容纳函数补写的结尾 NUL
        // 刻意沿用 ExAllocatePoolWithTag(不迁 ExAllocatePool2),局部抑制其 C4996 弃用告警。
#pragma warning(push)
#pragma warning(disable : 4996)
        PWCH  buf = static_cast<PWCH>(
            ExAllocatePoolWithTag(PagedPool, static_cast<SIZE_T>(cap) * sizeof(WCHAR), KLIB_PATH_TAG));
#pragma warning(pop)
        if (buf != NULL) {
            st = kernel_lib_get_process_path(pid, buf, cap, &needed);
            if (NT_SUCCESS(st)) {
                DbgPrint("cpp-wdm-sys: pid %lu path = %ws\n", pid, buf);
            } else {
                DbgPrint("cpp-wdm-sys: get_process_path(retry) failed, status = 0x%08X\n", st);
            }
            ExFreePoolWithTag(buf, KLIB_PATH_TAG);
        } else {
            DbgPrint("cpp-wdm-sys: ExAllocatePoolWithTag failed (%lu chars)\n", cap);
        }
    } else {
        DbgPrint("cpp-wdm-sys: get_process_path(probe) failed, status = 0x%08X\n", st);
    }

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
