#pragma once

// 第 1 个工程(Rust kernel-lib)以 C ABI(#[no_mangle] extern "C")导出的函数。
// x64 下符号名即 kernel_lib_add,无修饰、无前导下划线。
#ifdef __cplusplus
extern "C" {
#endif

int kernel_lib_add(int a, int b);

// 按 PID 取进程镜像的 NT 设备全路径,写入调用方 UTF-16 缓冲。
// 须在 PASSIVE_LEVEL 调用。返回 NTSTATUS:
//   STATUS_SUCCESS           已写入,*out_chars = 写入字符数(不含 NUL)。
//   STATUS_BUFFER_TOO_SMALL  缓冲不够,*out_chars = 所需字符数(不含 NUL)。
//   其他                     PsLookupProcessByProcessId / SeLocateProcessImageName 透传的错误。
// 依赖 NTSTATUS/ULONG/PWCH/PULONG,本头需在 <ntddk.h> 之后包含。
NTSTATUS kernel_lib_get_process_path(
    ULONG  pid,
    PWCH   out_buf,
    ULONG  buf_chars,
    PULONG out_chars);

#ifdef __cplusplus
}
#endif
