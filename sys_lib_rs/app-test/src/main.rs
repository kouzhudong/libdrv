//! app-test:用户态测试程序。
//!
//! 打开 rust-sys 驱动创建的符号链接 `\\.\RustWdmDemo`,通过
//! `IOCTL_GET_PROCESS_PATH` 传入一个 PID,取回该进程镜像的 NT 设备全路径。
//!
//! 用法:
//!   app-test            # 查自身进程
//!   app-test <pid>      # 查指定 PID
//!
//! 前置:rust-sys 驱动已加载(sc start),否则 CreateFileW 报 2(找不到文件)。

use std::ffi::c_void;

type Handle = *mut c_void;
type Bool = i32;

// kernel32 导入(手写 FFI,避免任何第三方依赖)。
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(name: *const u16, access: u32, share: u32, security: *mut c_void, disposition: u32, flags: u32, template: Handle) -> Handle;
    fn DeviceIoControl(
        device: Handle,
        code: u32,
        in_buf: *const c_void,
        in_len: u32,
        out_buf: *mut c_void,
        out_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
    fn GetLastError() -> u32;
    fn GetCurrentProcessId() -> u32;
}

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE: isize = -1;

// 以下四项必须与驱动端 (rust-sys/src/lib.rs) 完全一致。
const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;
const FUNCTION_GET_PROCESS_PATH: u32 = 0x800;

/// `CTL_CODE` 宏的 Rust 版,须与驱动端 `ctl_code` 一致。
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_GET_PROCESS_PATH: u32 = ctl_code(FILE_DEVICE_UNKNOWN, FUNCTION_GET_PROCESS_PATH, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// 设备符号链接(对应驱动的 `\??\RustWdmDemo`)。
const DEVICE_PATH: &str = r"\\.\RustWdmDemo";

/// 路径最长 32767 个 WCHAR(UNICODE_STRING.Length 为 USHORT),+1 容纳结尾 NUL。
const MAX_PATH_CHARS: usize = 32767;
const OUT_BUF_CHARS: usize = MAX_PATH_CHARS + 1;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn run() -> Result<(), String> {
    // PID:命令行参数优先,否则查自身。
    let pid: u32 = match std::env::args().nth(1) {
        Some(arg) => arg.parse::<u32>().map_err(|_| format!("非法 PID 参数: {arg}"))?,
        None => unsafe { GetCurrentProcessId() },
    };

    // 1) 打开设备。
    let wide = to_wide(DEVICE_PATH);
    let device = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if device as isize == INVALID_HANDLE {
        let gle = unsafe { GetLastError() };
        return Err(format!("打开 {DEVICE_PATH} 失败 (GetLastError={gle})。驱动是否已加载(sc start)?"));
    }

    // 2) 下发 IOCTL:输入 = u32 PID,输出 = UTF-16 路径。
    let mut out: Vec<u16> = vec![0u16; OUT_BUF_CHARS];
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            device,
            IOCTL_GET_PROCESS_PATH,
            &pid as *const u32 as *const c_void,
            size_of::<u32>() as u32,
            out.as_mut_ptr() as *mut c_void,
            (out.len() * size_of::<u16>()) as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let gle = unsafe { GetLastError() };
    unsafe { CloseHandle(device) };

    if ok == 0 {
        return Err(format!("DeviceIoControl 失败 (GetLastError={gle})。PID {pid} 可能不存在或无访问权限。"));
    }

    // 3) 解析返回:returned 为字节数(含结尾 NUL),取到首个 NUL 为止。
    let chars = (returned as usize) / size_of::<u16>();
    let slice = &out[..chars.min(out.len())];
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    let path = String::from_utf16_lossy(&slice[..end]);

    if path.is_empty() {
        println!("pid {pid} -> (空路径;PID 4=System 等无用户态镜像的进程会如此)");
    } else {
        println!("pid {pid} -> {path}");
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("app-test: {e}");
        std::process::exit(1);
    }
}
