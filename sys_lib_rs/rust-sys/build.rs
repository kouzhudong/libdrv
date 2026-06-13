//! 构建脚本:由 wdk-build 依据 WDK 配置注入驱动二进制所需的链接参数。
fn main() -> Result<(), wdk_build::ConfigError> {
    wdk_build::configure_wdk_binary_build()
}
