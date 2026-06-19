//! 02-rust-sys:用 windows-drivers-rs 写的 WDM 驱动。
//!
//! - DriverEntry 调用第 1 个工程 `kernel-lib` 导出的 `kernel_lib_add`(演示库链接)。
//! - 创建控制设备 `\Device\KernelLibGetPath` + 符号链接 `\??\KernelLibGetPath`,
//!   暴露 IOCTL `IOCTL_GET_PROCESS_PATH`:应用层传 PID,驱动回填该进程的 NT 设备全路径。
//!   配套用户态程序见同目录 `app-test`。
#![no_std]

extern crate alloc;

#[cfg(not(test))]
extern crate wdk_panic;

use kernel_lib::{kernel_lib_add, kernel_lib_get_process_path};
use wdk::println;
#[cfg(not(test))]
use wdk_alloc::WdkAllocator;
use wdk_sys::ntddk::{
    IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
    IofCompleteRequest, RtlInitUnicodeString,
};
use wdk_sys::{
    BOOLEAN, CCHAR, DRIVER_OBJECT, FALSE, FILE_ANY_ACCESS, FILE_DEVICE_UNKNOWN, IO_NO_INCREMENT,
    IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, METHOD_BUFFERED, NTSTATUS,
    PCUNICODE_STRING, PDEVICE_OBJECT, PIRP, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_PARAMETER, STATUS_SUCCESS, UNICODE_STRING, ULONG_PTR,
};

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

/// 把 ASCII 字面量转成 NUL 结尾的 UTF-16 数组(no_std 下无 widestring,内核名只含 ASCII)。
macro_rules! utf16z {
    ($s:literal) => {{
        const SRC: &str = $s;
        const LEN: usize = SRC.len() + 1;
        const ARR: [u16; LEN] = {
            let bytes = SRC.as_bytes();
            let mut out = [0u16; LEN];
            let mut i = 0;
            while i < bytes.len() {
                out[i] = bytes[i] as u16;
                i += 1;
            }
            out
        };
        ARR
    }};
}

/// 设备名(内核命名空间)与符号链接名(`\??\` 即 `\DosDevices\`,应用层以 `\\.\KernelLibGetPath` 打开)。
static DEVICE_NAME: &[u16] = &utf16z!("\\Device\\KernelLibGetPath");
static SYMLINK_NAME: &[u16] = &utf16z!("\\??\\KernelLibGetPath");

/// 自定义功能号:0x800 起为厂商自定义区(0x000..0x7FF 由微软保留)。
const FUNCTION_GET_PROCESS_PATH: u32 = 0x800;

/// `CTL_CODE` 宏的 Rust 版:`(DeviceType << 16) | (Access << 14) | (Function << 2) | Method`。
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// IOCTL:按 PID 取进程 NT 全路径。
/// 输入缓冲 = `u32` PID;输出缓冲 = UTF-16 路径(METHOD_BUFFERED,输入输出共用 SystemBuffer)。
/// 应用层须用同一数值(见 app-test)。
pub const IOCTL_GET_PROCESS_PATH: u32 = ctl_code(
    FILE_DEVICE_UNKNOWN,
    FUNCTION_GET_PROCESS_PATH,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS,
);

/// 由 `&[u16]`(含结尾 NUL)构造 `UNICODE_STRING`。
fn init_unicode_string(buf: &'static [u16]) -> UNICODE_STRING {
    let mut s: UNICODE_STRING = unsafe { core::mem::zeroed() };
    // SAFETY: buf 是 'static、NUL 结尾的宽字符串;RtlInitUnicodeString 按 NUL 计算长度。
    unsafe { RtlInitUnicodeString(&mut s, buf.as_ptr()) };
    s
}

/// WDM 驱动入口,符号名固定为 `DriverEntry`。
///
/// # Safety
/// 解引用由 WDM 传入的裸指针 `driver`。
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    // 演示库链接:调用第 1 个工程导出的函数(其内部 DbgPrint)。
    let sum = kernel_lib_add(2, 3);
    println!("rust-sys: kernel_lib_add(2, 3) = {sum}");

    // 1) 创建控制设备。
    let mut device: PDEVICE_OBJECT = core::ptr::null_mut();
    let mut dev_name = init_unicode_string(DEVICE_NAME);
    // SAFETY: 参数均有效;device 接收新建设备对象。
    let status = unsafe {
        IoCreateDevice(
            driver,
            0,
            &mut dev_name,
            FILE_DEVICE_UNKNOWN,
            0,
            FALSE as BOOLEAN,
            &mut device,
        )
    };
    if status < 0 {
        println!("rust-sys: IoCreateDevice failed, status = {status:#010x}");
        return status;
    }

    // 2) 创建符号链接,供应用层以 \\.\KernelLibGetPath 打开。
    let mut dev_name2 = init_unicode_string(DEVICE_NAME);
    let mut link_name = init_unicode_string(SYMLINK_NAME);
    // SAFETY: 两个 UNICODE_STRING 均有效。
    let status = unsafe { IoCreateSymbolicLink(&mut link_name, &mut dev_name2) };
    if status < 0 {
        println!("rust-sys: IoCreateSymbolicLink failed, status = {status:#010x}");
        // SAFETY: device 由步骤 1 创建,此处回滚删除。
        unsafe { IoDeleteDevice(device) };
        return status;
    }

    // 3) 注册分发例程。
    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_device_control);
    driver.DriverUnload = Some(driver_exit);

    println!("rust-sys: device \\Device\\KernelLibGetPath ready");
    STATUS_SUCCESS
}

/// CREATE / CLOSE:无状态,直接成功完成。
unsafe extern "C" fn dispatch_create_close(_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    // SAFETY: irp 由 IO 管理器传入,有效。
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
    }
    STATUS_SUCCESS
}

/// DEVICE_CONTROL:处理 `IOCTL_GET_PROCESS_PATH`。
///
/// METHOD_BUFFERED:输入输出共用 `Irp->AssociatedIrp.SystemBuffer`,
/// 故先把 PID 拷到局部,再把路径写回同一缓冲。
unsafe extern "C" fn dispatch_device_control(_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    let mut status = STATUS_INVALID_DEVICE_REQUEST;
    let mut info: ULONG_PTR = 0;

    // SAFETY: irp 有效;取当前 IO 栈位置(等价 IoGetCurrentIrpStackLocation)。
    unsafe {
        let stack = (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation;
        let ioctl = (*stack).Parameters.DeviceIoControl.IoControlCode;
        let in_len = (*stack).Parameters.DeviceIoControl.InputBufferLength;
        let out_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength;
        let sysbuf = (*irp).AssociatedIrp.SystemBuffer;

        if ioctl == IOCTL_GET_PROCESS_PATH {
            if sysbuf.is_null() || (in_len as usize) < core::mem::size_of::<u32>() {
                status = STATUS_INVALID_PARAMETER;
            } else {
                // 先读出 PID(输出阶段会覆写同一缓冲)。
                let pid = core::ptr::read_unaligned(sysbuf as *const u32);
                let out_chars = out_len / (core::mem::size_of::<u16>() as u32);
                let mut needed: u32 = 0;
                status = kernel_lib_get_process_path(
                    pid,
                    sysbuf as *mut u16,
                    out_chars,
                    &mut needed,
                );
                // 成功时回报写入字节数(含结尾 NUL),供应用层据 BytesReturned 取串。
                if status >= 0 {
                    info = ((needed as usize + 1) * core::mem::size_of::<u16>()) as ULONG_PTR;
                }
            }
        }

        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = info;
        IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
    }
    status
}

/// 卸载:删符号链接 + 删设备。
///
/// # Safety
/// 解引用由 WDM 传入的 `driver` 裸指针。
unsafe extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {
    println!("rust-sys: DriverUnload");
    let mut link_name = init_unicode_string(SYMLINK_NAME);
    // SAFETY: link_name 有效;driver 非空且仅创建了一个设备。
    unsafe {
        // 卸载阶段无从恢复,删除失败也只能忽略返回值。
        let _ = IoDeleteSymbolicLink(&mut link_name);
        let device = (*driver).DeviceObject;
        if !device.is_null() {
            IoDeleteDevice(device);
        }
    }
}
