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

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
