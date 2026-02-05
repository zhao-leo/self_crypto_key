fn main() {
    // 检查目标操作系统
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // 此 crate 仅支持 Linux 平台（使用 ELF 格式的二进制文件）
    if target_os != "linux" {
        panic!(
            "\n\n\
            ╔════════════════════════════════════════════════════════════════════════╗\n\
            ║  错误：不支持的目标平台                                                ║\n\
            ╠════════════════════════════════════════════════════════════════════════╣\n\
            ║                                                                        ║\n\
            ║  此 crate 仅支持使用 ELF 二进制格式的 Linux 平台。                     ║\n\
            ║                                                                        ║\n\
            ║  当前目标平台：                                                        ║\n\
            ║    操作系统： {:<56} ║\n\
            ║    架构：     {:<56} ║\n\
            ║    环境：     {:<56} ║\n\
            ║                                                                        ║\n\
            ║  支持的目标平台包括：                                                  ║\n\
            ║    • x86_64-unknown-linux-gnu                                          ║\n\
            ║    • x86_64-unknown-linux-musl                                         ║\n\
            ║    • aarch64-unknown-linux-gnu                                         ║\n\
            ║    • aarch64-unknown-linux-musl                                        ║\n\
            ║    • 其他使用 ELF 格式的 Linux 目标平台                                ║\n\
            ║                                                                        ║\n\
            ║  原因：                                                                ║\n\
            ║  本库依赖于 Linux 特定的系统调用和 ELF 二进制格式来实现                ║\n\
            ║  自修改加密密钥存储功能。                                              ║\n\
            ║                                                                        ║\n\
            ╚════════════════════════════════════════════════════════════════════════╝\n\
            ",
            target_os,
            target_arch,
            if target_env.is_empty() {
                "gnu (默认)"
            } else {
                &target_env
            }
        );
    }

    // 如果需要，可以设置重新运行的条件
    println!("cargo:rerun-if-changed=build.rs");
}
