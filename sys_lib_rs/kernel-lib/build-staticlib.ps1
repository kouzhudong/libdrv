# 产出 kernel_lib.lib(供第 3 个 C++ WDM 驱动链接)。
# 关键:必须走 rustup 的 MSVC 工具链,故把 ~/.cargo/bin 前置到 PATH,
# 避免 chocolatey 的独立 gnu rustc(见根目录 README“工具链陷阱”)。
$ErrorActionPreference = "Stop"
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
Set-Location $PSScriptRoot

# crate-type 默认是 rlib;这里临时以 staticlib 形式编译,并开启 panic-handler feature
# (no_std 静态库自身链接需要 #[panic_handler])。
cargo rustc --release --features panic-handler --crate-type staticlib

Write-Host "`n产物: $PSScriptRoot\target\release\kernel_lib.lib"
