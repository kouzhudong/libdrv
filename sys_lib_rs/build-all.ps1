# 一键编译三个工程(按依赖顺序)。普通(非提权)PowerShell 即可编译。
# 注意:加载/运行驱动需另行测试签名 + 管理员,见 README。
$ErrorActionPreference = "Stop"
# 让 cargo / rustc 走 rustup 的 MSVC 工具链(绕开 PATH 上 chocolatey 的 gnu rustc)
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$root = $PSScriptRoot

Write-Host "==> [1/3] 编译 kernel-lib 静态库 (kernel_lib.lib)" -ForegroundColor Cyan
Set-Location "$root\kernel-lib"
cargo rustc --release --features panic-handler --crate-type staticlib
if ($LASTEXITCODE) { throw "kernel-lib staticlib 失败" }

Write-Host "==> [2/3] 编译 rust-sys WDM 驱动 (rust_sys.dll)" -ForegroundColor Cyan
Set-Location "$root\rust-sys"
cargo build --release
if ($LASTEXITCODE) { throw "rust-sys 失败" }
Copy-Item "$root\rust-sys\target\release\rust_sys.dll" "$root\rust-sys\target\release\rust_sys.sys" -Force

Write-Host "==> [3/3] 编译 cpp-wdm-sys C++ WDM 驱动 (cpp-wdm-sys.sys)" -ForegroundColor Cyan
$msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1
& $msbuild "$root\cpp-wdm-sys\cpp-wdm-sys.vcxproj" /p:Configuration=Release /p:Platform=x64 /nologo /v:minimal
if ($LASTEXITCODE) { throw "cpp-wdm-sys 失败" }

Write-Host "`n全部完成。产物:" -ForegroundColor Green
Write-Host "  01: $root\kernel-lib\target\release\kernel_lib.lib  (+ libkernel_lib.rlib)"
Write-Host "  02: $root\rust-sys\target\release\rust_sys.sys"
Write-Host "  03: $root\cpp-wdm-sys\x64\Release\cpp-wdm-sys.sys"
