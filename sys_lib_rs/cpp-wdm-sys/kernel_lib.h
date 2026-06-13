#pragma once

// 第 1 个工程(Rust kernel-lib)以 C ABI(#[no_mangle] extern "C")导出的函数。
// x64 下符号名即 kernel_lib_add,无修饰、无前导下划线。
#ifdef __cplusplus
extern "C" {
#endif

int kernel_lib_add(int a, int b);

#ifdef __cplusplus
}
#endif
