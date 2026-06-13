//! kernel-lib:供 sys 工程使用的 windows-drivers-rs 内核库。
//!
//! 用 `wdk-sys` 的 ntddk 绑定(`DbgPrint`),导出一个 C ABI 函数 `kernel_lib_add`。
//! 同时产出 `rlib`(给 Rust 驱动)与 `staticlib`(`kernel_lib.lib`,给 C++ 驱动)。
#![no_std]

use wdk_sys::ntddk::DbgPrint;

/// 导出给 sys 调用的函数:用 `DbgPrint` 打一行日志,返回 `a + b`。
///
/// 以 `extern "C"` + `#[unsafe(no_mangle)]` 导出,符号名固定为 `kernel_lib_add`,
/// 可被 Rust 直接调用,也可被 C/C++ 通过 `extern "C"` 链接调用。
#[unsafe(no_mangle)]
pub extern "C" fn kernel_lib_add(a: i32, b: i32) -> i32 {
    // SAFETY: 格式串是编译期 null 结尾 C 字面量,两个 %d 与两个 i32 变参匹配。
    unsafe {
        DbgPrint(
            c"[kernel-lib] kernel_lib_add(%d, %d)\n".as_ptr().cast(),
            a,
            b,
        );
    }
    a + b
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
