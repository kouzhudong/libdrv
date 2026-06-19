# Rust(windows-drivers-rs)+ C++(WDK)内核驱动互操作示例

三个工程演示「一个 Rust 内核库导出 C ABI 函数,分别被 Rust 驱动和 C++ WDM 驱动调用」。

```
test/
├── kernel-lib/      Rust 库(windows-drivers-rs / wdk-sys),导出 extern "C" kernel_lib_add
│                        + kernel_lib_get_process_path(按 PID 取进程 NT 全路径)
│                        产出 libkernel_lib.rlib(给 02 用) + kernel_lib.lib(给 03 用)
├── rust-sys/        Rust WDM 驱动(windows-drivers-rs),DriverEntry 调 kernel_lib_add;
│                        并创建控制设备 \Device\RustWdmDemo + 符号链接,经 IOCTL 暴露取路径功能
├── cpp-wdm-sys/     C++ WDM 驱动(WDK MSBuild),DriverEntry 链接并调 kernel_lib_add
├── app-test/        用户态 Rust EXE,经 \\.\RustWdmDemo 与 rust-sys 通讯,按 PID 查全路径
├── build-all.ps1       一键编译四者
└── README.md
```

调用关系:

```
            kernel-lib (01)  ──导出 extern "C" int kernel_lib_add(int,int)──┐
              │  内部调 DbgPrint                                            │
   ┌──────────┴───────────┐                                                │
   │ rlib                  │ staticlib (kernel_lib.lib)                     │
   ▼                       ▼                                                ▼
rust-sys (02)          cpp-wdm-sys (03) ── extern "C" 声明 + 链接 ──→ 调用同一函数
Rust WDM 驱动           C++ WDM 驱动
```

`kernel_lib_add(2, 3)` 会 `DbgPrint` 一行并返回 `5`,两个驱动各自再打印一行。

---

## 一、编译环境(本机已具备,供复现参考)

| 组件 | 本机版本 / 路径 | 说明 |
|------|----------------|------|
| Rust 工具链 | `stable-x86_64-pc-windows-msvc` 1.93.1(rustup) | **必须 MSVC,不能用 gnu**,见下方“工具链陷阱” |
| cargo-make | 0.37.24 | 仅 `cargo make` 完整打包时需要 |
| LLVM/Clang | `C:\Program Files\LLVM\bin\libclang.dll`,`LIBCLANG_PATH` 已设 | wdk-sys 用 bindgen 生成绑定 |
| WDK + SDK | `10.0.28000.0`(`WDKContentRoot=C:\Program Files (x86)\Windows Kits\10`) | km 头/库唯一可用版本 |
| Visual Studio | Enterprise 2026(v180),含 `WindowsKernelModeDriver10.0` 工具集 | 编译 C++ WDM 驱动 |

crate 版本(注意生态版本错位):

- `wdk` / `wdk-alloc` / `wdk-panic` = **0.4.1**
- `wdk-sys` / `wdk-build` / `wdk-macros` = **0.5.1**(`wdk` 0.4.1 自身依赖 `wdk-sys ^0.5.1`,组合是兼容的)

### ⚠️ 工具链陷阱(本机最大的坑)

本机 PATH 上 `C:\ProgramData\chocolatey\bin` 排在 `%USERPROFILE%\.cargo\bin` **前面**,且 chocolatey 装了一个独立的
`rustc/cargo 1.85.0`,host 是 **`x86_64-pc-windows-gnu`**。结果:即便用 rustup 选了 msvc 工具链,cargo 去 PATH 找
`rustc` 时仍命中 chocolatey 的 gnu rustc,产出 gnu 格式的 `.a`/rlib —— 既链不进 MSVC 的 C++ 驱动,也不是内核驱动该用的 ABI。

**编译前务必让 rustup 代理优先**(本仓库所有脚本都这么做):

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
```

永久修复(任选其一):
- 把 `%USERPROFILE%\.cargo\bin` 移到 PATH 最前;或
- `choco uninstall rust`(卸掉那个 gnu 版,统一用 rustup)。

各工程已带 `rust-toolchain.toml` 钉死 msvc,但**仅当通过 rustup 代理调用 cargo 时才生效**(独立的 chocolatey cargo 会忽略它)。

---

## 二、编译(普通非提权 PowerShell 即可)

一键:

```powershell
powershell -File .\build-all.ps1
```

或手动按序(注意每步先 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"`):

```powershell
# 1) 先编 Rust 静态库(给 03 链接)。crate-type 默认 rlib,这里临时以 staticlib 产出
cd kernel-lib
cargo rustc --release --features panic-handler --crate-type staticlib
#   -> target\release\kernel_lib.lib   以及作为依赖会自动产出的 libkernel_lib.rlib

# 2) Rust WDM 驱动(把 01 当普通 rlib 依赖)
cd ..\rust-sys
cargo build --release
#   -> target\release\rust_sys.dll  (改名即 .sys)

# 3) C++ WDM 驱动(链接 01 的 kernel_lib.lib)
cd ..\cpp-wdm-sys
& "<MSBuild.exe>" cpp-wdm-sys.vcxproj /p:Configuration=Release /p:Platform=x64
#   -> x64\Release\cpp-wdm-sys.sys
```

已验证产物:

| 工程 | 产物 | 大小 |
|------|------|------|
| kernel-lib | `target\release\kernel_lib.lib` + `libkernel_lib.rlib` | 2.9 MB / 7 KB |
| rust-sys | `target\release\rust_sys.sys` | 14.8 KB |
| cpp-wdm-sys | `x64\Release\cpp-wdm-sys.sys` | 5 KB |

---

## 三、几个关键设计点(为什么这么写)

1. **kernel-lib 默认只产 `rlib`。** 若把 `staticlib` 也写进 `[lib] crate-type`,它会随依赖一起被编译,而
   no_std 的 staticlib 强制要求 `#[panic_handler]`,导致 02 编译失败。故 `.lib` 改用 `cargo rustc --crate-type staticlib` 单独产出。
2. **`#[panic_handler]` 用 `panic-handler` feature 门控。** 独立 `.lib`(无 Rust 运行时)需要自带 panic 处理器;
   作为 rlib 被 02 依赖时不能带,否则与 02 的 `wdk-panic` 重复定义 `panic_impl`。
3. **`crt-static`。** 02 的 `.cargo\config.toml` 设 `target-feature=+crt-static`,否则 wdk-build 报 `StaticCrtNotEnabled`。
   注意 `.cargo\config.toml` 按**当前工作目录**生效,必须 `cd` 进工程目录再 `cargo build`。
4. **C++ 侧 `/utf-8`。** 源码含中文注释,CP936 系统下 MSVC 会按 GBK 误解码报 C4819(WDK 默认 warnings-as-errors)。已在 vcxproj 加 `/utf-8`。
5. **`SignMode=Off`。** WDK 默认构建期自动测试签名,本机无测试证书会报 signtool 错。关掉,签名作为独立运行期步骤(见下)。
6. **C++ 链接 Rust 静态库无未定义符号:** `memcpy/memset/DbgPrint` 等由 `ntoskrnl.exe` 提供,WDM 工具集默认已链 `ntoskrnl.lib`。

---

## 四、运行环境(加载驱动)—— 需要管理员 + 测试签名

> 加载未签名内核驱动会改系统启动状态,**强烈建议在虚拟机 / 已打快照的环境里操作**。

### 1. 开启测试签名模式(管理员 + 重启)

```powershell
bcdedit /set testsigning on
# 若开了安全启动(Secure Boot),需先在固件里关闭,否则 testsigning 不生效。
# 若开了内存完整性 / HVCI,也建议关闭(设置 > 核心隔离),否则未签名/测试签名驱动可能被拦。
shutdown /r /t 0
```
重启后桌面右下角会显示“测试模式”。

### 2. 生成测试证书并签名 .sys(管理员)

```powershell
# 用 WDK/SDK 自带工具(在 "Developer Command Prompt" 里更方便):
makecert -r -pe -ss PrivateCertStore -n "CN=TestDriverCert" testcert.cer
certmgr /add testcert.cer /s /r localMachine root
certmgr /add testcert.cer /s /r localMachine trustedpublisher

signtool sign /v /s PrivateCertStore /n TestDriverCert /fd SHA256 `
    /t http://timestamp.digicert.com .\cpp-wdm-sys\x64\Release\cpp-wdm-sys.sys
# 同样可签 .\rust-sys\target\release\rust_sys.sys
```

### 3. 安装 / 启动 / 卸载(管理员)

```powershell
sc.exe create cppwdmsys type= kernel binPath= "C:\...\cpp-wdm-sys\x64\Release\cpp-wdm-sys.sys"
sc.exe start  cppwdmsys      # 触发 DriverEntry
sc.exe stop   cppwdmsys      # 触发 DriverUnload
sc.exe delete cppwdmsys
# rust_sys 同理(服务名换成 rustsys,binPath 指向 rust_sys.sys)
```

### 4. 看 DbgPrint 输出

用 Sysinternals **DebugView**(管理员运行,勾 `Capture > Capture Kernel`),`sc start` 时应看到:

```
[kernel-lib] kernel_lib_add(2, 3)
cpp-wdm-sys: kernel_lib_add(2, 3) = 5      # 或 rust-sys: kernel_lib_add(2, 3) = 5
```

> 提示:Win10/11 默认会过滤 `DbgPrint`。如看不到,设注册表
> `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter`,新建 DWORD `DEFAULT = 0xFFFFFFFF` 后重启。

---

## 六、用户态测试(app-test ↔ rust-sys 通讯设备)

rust-sys 在 DriverEntry 里创建了控制设备:

- 设备名:`\Device\RustWdmDemo`
- 符号链接:`\??\RustWdmDemo`(应用层以 `\\.\RustWdmDemo` 打开)
- IOCTL:`IOCTL_GET_PROCESS_PATH = 0x00222000`(`CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)`)
  - 输入缓冲:`u32` PID(METHOD_BUFFERED,输入输出共用 SystemBuffer)
  - 输出缓冲:UTF-16 路径;成功时 `BytesReturned` = 路径字节数(含结尾 NUL)
  - 内部调 `kernel_lib_get_process_path`,即 `kernel-lib` 导出的同一函数

`app-test`(用户态 Rust EXE,手写 FFI 调 kernel32,无第三方依赖)演示完整通讯:

```powershell
# 先确保 rust-sys 驱动已加载(见第四节:测试签名 + sc create/start)
sc.exe create rustsys type= kernel binPath= "<...>\rust-sys\target\release\rust_sys.sys"
sc.exe start  rustsys

# 查自身进程全路径
.\app-test\target\release\app-test.exe
# pid 12345 -> \Device\HarddiskVolume3\...\app-test.exe

# 查指定 PID(从任务管理器/tasklist 取一个真实 PID)
.\app-test\target\release\app-test.exe 1234
```

要点:

- 返回的是 **NT 设备路径**(`\Device\HarddiskVolumeX\...`),非盘符路径。
- 查 PID 4(System)等无用户态镜像的进程会得到**空路径**,这是正常现象(`SeLocateProcessImageName` 对其返回空串)。
- `app-test` 输出缓冲按最大 32767 WCHAR(+NUL)分配,单次 IOCTL 即可覆盖任意长度路径,无需二次调用。
- 打开设备报 `GetLastError=2` 表示驱动未加载。

---

## 五、其他未尽事宜 / 提醒

- **`cargo make` 完整打包(生成 .inf/.cat 并测试签名)在本会话不可用。** wdk-build 的 `load_rust_driver_makefile()`
  用**符号链接**把 makefile 链进 `target\`,需要 `SeCreateSymbolicLinkPrivilege`。本机当前会话是非提权(Medium 完整性)、
  开发者模式未开,故失败(`os error 1314 客户端没有所需的特权`)。两种解法:
  - 开**开发者模式**(管理员):
    ```powershell
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 1 /f
    ```
  - 或在**管理员 PowerShell** 里跑 `cargo make`。

  本示例已用 `cargo build` + 手动改名 `.sys` 替代,编译产物等价;`cargo make` 只是多了 .inf/.cat 打包与自动测试签名。
- **仅编译不需要管理员;加载运行需要管理员 + 测试签名 + 重启。**
- **架构固定 x64。** 三工程都按 `x86_64` / `x64`。换 ARM64 需相应改 target 与平台。
- **WDK 版本耦合:** 03 的 `WindowsTargetPlatformVersion=10.0.28000.0` 是本机唯一装了 km 头/库的版本;换机器需对应改。
- 改动停在 working tree,未做任何 git 提交。
