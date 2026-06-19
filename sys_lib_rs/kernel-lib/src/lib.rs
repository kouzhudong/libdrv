//! kernel-lib:供 sys 工程使用的 windows-drivers-rs 内核库。
//!
//! 用 `wdk-sys` 的 ntddk 绑定(`DbgPrint`),导出一个 C ABI 函数 `kernel_lib_add`。
//! 同时产出 `rlib`(给 Rust 驱动)与 `staticlib`(`kernel_lib.lib`,给 C++ 驱动)。
#![no_std]

use wdk_sys::ntddk::{DbgPrint, ExFreePool, ObfDereferenceObject, PsLookupProcessByProcessId, SeLocateProcessImageName};
use wdk_sys::{HANDLE, NTSTATUS, PEPROCESS, PUNICODE_STRING, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

/// 导出给 sys 调用的函数:用 `DbgPrint` 打一行日志,返回 `a + b`。
///
/// 以 `extern "C"` + `#[unsafe(no_mangle)]` 导出,符号名固定为 `kernel_lib_add`,
/// 可被 Rust 直接调用,也可被 C/C++ 通过 `extern "C"` 链接调用。
#[unsafe(no_mangle)]
pub extern "C" fn kernel_lib_add(a: i32, b: i32) -> i32 {
    // SAFETY: 格式串是编译期 null 结尾 C 字面量,两个 %d 与两个 i32 变参匹配。
    unsafe {
        DbgPrint(c"[kernel-lib] kernel_lib_add(%d, %d)\n".as_ptr().cast(), a, b);
    }
    a + b
}

/// 按 PID 取进程镜像的 **NT 设备全路径**(形如 `\Device\HarddiskVolume3\Windows\System32\xxx.exe`)。
///
/// 调用方供 UTF-16(WCHAR) 缓冲,规避跨语言/跨分配器的所有权问题:
/// - `pid`        进程 ID(0 视作非法)。
/// - `out_buf`    WCHAR 缓冲;可为 null(仅探测所需长度)。
/// - `buf_chars`  `out_buf` 容量(WCHAR 数,需含结尾 NUL 的位置)。
/// - `out_chars`  [out] 成功=写入字符数(不含 NUL);`STATUS_BUFFER_TOO_SMALL`=所需字符数(不含 NUL)。
///
/// 路径长度上限由 `UNICODE_STRING.Length`(`USHORT`)决定:最多 65534 字节 = **32767 个 WCHAR**。
/// 故调用方典型用法是「先传 null 探长度,再按 `*out_chars + 1` 堆分配重试」——切勿在内核栈上开 64KB 缓冲。
///
/// 返回 NTSTATUS。**须在 PASSIVE_LEVEL 调用**(`SeLocateProcessImageName`/`PsLookupProcessByProcessId` 的要求)。
///
/// 以 `extern "C"` + `#[unsafe(no_mangle)]` 导出,符号名固定 `kernel_lib_get_process_path`,
/// Rust 与 C/C++ 共用。
///
/// # Safety
/// `out_buf` 须指向至少 `buf_chars` 个可写 WCHAR,或为 null;`out_chars` 须指向可写 `u32`(为 null 时返回非法参数)。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_lib_get_process_path(pid: u32, out_buf: *mut u16, buf_chars: u32, out_chars: *mut u32) -> NTSTATUS {
    if pid == 0 || out_chars.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    // 1) PID -> PEPROCESS(加引用,末尾必须 ObfDereferenceObject 释放)。
    let mut process: PEPROCESS = core::ptr::null_mut();
    // SAFETY: pid 转 HANDLE 是内核 PID 的标准约定;process 指向本地可写指针。
    let status = unsafe { PsLookupProcessByProcessId(pid as usize as HANDLE, &mut process) };
    if status < 0 {
        return status;
    }

    // 2) 取镜像名(内核池分配 UNICODE_STRING,末尾必须 ExFreePool 释放)。
    let mut image_name: PUNICODE_STRING = core::ptr::null_mut();
    // SAFETY: process 已由步骤 1 加引用;image_name 指向本地可写指针。
    let status = unsafe { SeLocateProcessImageName(process, &mut image_name) };
    if status < 0 {
        // SAFETY: process 由步骤 1 加引用,此处释放。
        unsafe { ObfDereferenceObject(process.cast()) };
        return status;
    }
    // 防御:成功却回传空指针属反常,直接判失败,避免后续解空指针。
    if image_name.is_null() {
        // SAFETY: process 由步骤 1 加引用,此处释放。
        unsafe { ObfDereferenceObject(process.cast()) };
        return STATUS_UNSUCCESSFUL;
    }

    // 3) 拷贝 + 收尾。UNICODE_STRING.Length 是字节数,字符数 = Length / size_of::<WCHAR>。
    // Length 为 USHORT,needed_chars <= 32767,后续 needed_chars + 1 不会溢出 u32。
    // SAFETY: image_name 已判非空。
    let needed_chars = unsafe { (*image_name).Length } as u32 / (core::mem::size_of::<u16>() as u32);
    // SAFETY: out_chars 已判非空。先写所需长度(供调用方据此重试或扩容)。
    unsafe { *out_chars = needed_chars };

    let result = if out_buf.is_null() || buf_chars < needed_chars + 1 {
        STATUS_BUFFER_TOO_SMALL
    } else {
        // SAFETY: image_name.Buffer 指向 needed_chars 个 WCHAR;out_buf 容量已校验 >= needed_chars + 1。
        unsafe {
            // needed_chars==0 时 Buffer 可能为空,跳过拷贝,避免对空指针调用 copy_nonoverlapping。
            if needed_chars > 0 {
                core::ptr::copy_nonoverlapping((*image_name).Buffer, out_buf, needed_chars as usize);
            }
            // 源 UNICODE_STRING 不保证 NUL 结尾,自补一个,供 C 侧 %ws 安全打印。
            *out_buf.add(needed_chars as usize) = 0;
        }
        STATUS_SUCCESS
    };

    // SAFETY: image_name 为 SeLocateProcessImageName 用内核池分配,此处释放;process 解引用。
    unsafe {
        ExFreePool(image_name.cast());
        ObfDereferenceObject(process.cast());
    }
    result
}

/// no_std 静态库自身链接时所需的 panic 处理器。
///
/// 仅当以独立 `.lib` 链接进 C++ 驱动(无 Rust 运行时)时开启 `panic-handler` feature;
/// 作为 rlib 被 Rust 驱动消费时不开,处理器由该驱动的 `wdk-panic` 提供,避免重复定义。
#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
