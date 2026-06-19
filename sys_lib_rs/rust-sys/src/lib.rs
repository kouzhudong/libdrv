//! 02-rust-sys:用 windows-drivers-rs 写的 WDM 驱动。
//!
//! DriverEntry 里调用第 1 个工程 `kernel-lib` 导出的 `kernel_lib_add`。
#![no_std]

extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

use kernel_lib::{kernel_lib_add, kernel_lib_get_process_path};
use wdk::println;
#[cfg(not(test))]
use wdk_alloc::WdkAllocator;
use wdk_sys::ntddk::PsGetCurrentProcessId;
use wdk_sys::{
    DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS,
};

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

    // 取当前进程的 NT 设备全路径(DriverEntry 在 PASSIVE_LEVEL,满足要求)。
    // 先传 null 探所需长度,再按需堆分配重试——路径最长 32767 WCHAR(64KB),不能放栈。
    // SAFETY: PsGetCurrentProcessId 返回当前进程 HANDLE。
    let pid = unsafe { PsGetCurrentProcessId() } as usize as u32;
    let mut needed: u32 = 0;
    // SAFETY: out_buf 传 null 仅探长度;needed 为本地可写 u32。
    let probe = unsafe { kernel_lib_get_process_path(pid, core::ptr::null_mut(), 0, &mut needed) };
    if probe == STATUS_BUFFER_TOO_SMALL {
        // +1 容纳函数补写的结尾 NUL;WdkAllocator 背后的堆分配,Vec 析构自动释放。
        let mut buf = alloc::vec![0u16; needed as usize + 1];
        let cap = buf.len() as u32;
        // SAFETY: buf 指向 cap 个可写 WCHAR;needed 为可写 u32。
        let status =
            unsafe { kernel_lib_get_process_path(pid, buf.as_mut_ptr(), cap, &mut needed) };
        if status >= 0 {
            let path = alloc::string::String::from_utf16_lossy(&buf[..needed as usize]);
            println!("rust-sys: pid {pid} path = {path}");
        } else {
            println!("rust-sys: get_process_path(retry) failed, status = {status:#010x}");
        }
    } else {
        println!("rust-sys: get_process_path(probe) failed, status = {probe:#010x}");
    }

    driver.DriverUnload = Some(driver_exit);
    STATUS_SUCCESS
}

extern "C" fn driver_exit(_driver: *mut DRIVER_OBJECT) {
    println!("rust-sys: DriverUnload");
}
