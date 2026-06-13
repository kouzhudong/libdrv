//! 02-rust-sys:用 windows-drivers-rs 写的 WDM 驱动。
//!
//! DriverEntry 里调用第 1 个工程 `kernel-lib` 导出的 `kernel_lib_add`。
#![no_std]

extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

use kernel_lib::kernel_lib_add;
use wdk::println;
#[cfg(not(test))]
use wdk_alloc::WdkAllocator;
use wdk_sys::{DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_SUCCESS};

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

/// WDM 驱动入口,符号名固定为 `DriverEntry`。
///
/// # Safety
/// 解引用由 WDM 传入的裸指针 `driver`。
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    // 调用第 1 个工程导出的函数;其内部会 DbgPrint,这里再打印返回值。
    let sum = kernel_lib_add(2, 3);
    println!("rust-sys: kernel_lib_add(2, 3) = {sum}");

    driver.DriverUnload = Some(driver_exit);
    STATUS_SUCCESS
}

extern "C" fn driver_exit(_driver: *mut DRIVER_OBJECT) {
    println!("rust-sys: DriverUnload");
}
