//! 基本使用示例
//!
//! 展示如何使用 self_crypto_key 库来存储和管理自修改密钥

use self_crypto_key::{init_key_storage, KeyStore};
use std::env;

// 初始化密钥存储空间（8KB总容量）
init_key_storage!();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    match args[1].as_str() {
        "init" => {
            // 初始化并生成随机密钥
            println!("初始化密钥存储...");
            let mut store = KeyStore::new()?;
            let random_key = KeyStore::generate_random_key(32);
            store.update(&random_key)?;
            println!("✓ 密钥已初始化: {}", random_key);
            println!("  (密钥已分散加密存储在多个section中)");
        }

        "show" => {
            // 显示当前密钥
            let store = KeyStore::new()?;
            match store.read() {
                Ok(key) => {
                    if key.is_empty() {
                        println!("密钥未初始化，请先运行: {} init", args[0]);
                    } else {
                        println!("当前密钥: {}", key);
                        println!("密钥长度: {} 字节", key.len());
                    }
                }
                Err(e) => {
                    eprintln!("读取密钥失败: {}", e);
                    eprintln!("提示: 可能需要先运行 {} init", args[0]);
                }
            }
        }

        "show-bytes" => {
            // 显示当前密钥（bytes格式）
            let store = KeyStore::new()?;
            match store.read_bytes() {
                Ok(bytes) => {
                    if bytes.is_empty() {
                        println!("密钥未初始化，请先运行: {} init", args[0]);
                    } else {
                        println!("当前密钥 (bytes): {:?}", bytes);
                        println!("密钥长度: {} 字节", bytes.len());

                        // 尝试显示为字符串
                        if let Ok(s) = String::from_utf8(bytes.clone()) {
                            println!("密钥 (string): {}", s);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("读取密钥失败: {}", e);
                }
            }
        }

        "update" => {
            // 更新密钥
            if args.len() < 3 {
                eprintln!("用法: {} update <新密钥>", args[0]);
                return Ok(());
            }

            let new_key = &args[2];
            let mut store = KeyStore::new()?;
            store.update(new_key)?;
            println!("✓ 密钥已更新为: {}", new_key);
        }

        "update-bytes" => {
            // 更新密钥（bytes）
            if args.len() < 3 {
                eprintln!("用法: {} update-bytes <hex字符串>", args[0]);
                eprintln!("示例: {} update-bytes 48656c6c6f", args[0]);
                return Ok(());
            }

            // 解析hex字符串为bytes
            let hex_str = &args[2];

            if hex_str.len() % 2 != 0 {
                eprintln!("错误: hex字符串长度必须是偶数");
                return Ok(());
            }

            let bytes: Result<Vec<u8>, _> = (0..hex_str.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
                .collect();

            match bytes {
                Ok(bytes) => {
                    let mut store = KeyStore::new()?;
                    store.update_bytes(&bytes)?;
                    println!("✓ 密钥已更新 (bytes): {:?}", bytes);
                    println!("  长度: {} 字节", bytes.len());
                }
                Err(e) => {
                    eprintln!("错误: 无效的hex字符串: {}", e);
                }
            }
        }

        "random" => {
            // 生成并设置随机密钥
            let length = if args.len() >= 3 {
                args[2].parse().unwrap_or(32)
            } else {
                32
            };

            let mut store = KeyStore::new()?;
            let capacity = store.capacity();

            if length > capacity {
                eprintln!("错误: 密钥长度({})不能超过总容量({})", length, capacity);
                return Ok(());
            }

            let random_key = KeyStore::generate_random_key(length);
            store.update(&random_key)?;
            println!("✓ 已生成并设置随机密钥: {}", random_key);
            println!("  长度: {} 字节", length);
        }

        "random-bytes" => {
            // 生成并设置随机bytes
            let length = if args.len() >= 3 {
                args[2].parse().unwrap_or(32)
            } else {
                32
            };

            let mut store = KeyStore::new()?;
            let capacity = store.capacity();

            if length > capacity {
                eprintln!("错误: 密钥长度({})不能超过总容量({})", length, capacity);
                return Ok(());
            }

            let random_bytes = KeyStore::generate_random_bytes(length);
            store.update_bytes(&random_bytes)?;
            println!("✓ 已生成并设置随机bytes: {:?}", random_bytes);
            println!("  长度: {} 字节", length);
        }

        "info" => {
            // 显示密钥存储信息
            let store = KeyStore::new()?;
            println!("密钥存储信息:");
            println!("  总容量: {} 字节 (8KB)", store.capacity());
            println!("  加密方式: 基于 .text 代码段哈希的分散加密");
            println!("  支持类型: String 和 Bytes");
            println!();
            println!("安全特性:");
            println!("  - 密钥分散存储在 4-8 个随机选择的 sections 中");
            println!("  - 每个片段使用 .text 段的 SHA256 哈希加密");
            println!("  - 应用多层混淆（位反转、字节置换、异或）");
            println!("  - 只有完整且未修改的程序才能正确恢复密钥");
            println!();
            println!("Section命名:");
            println!("  - 数据sections: .key_data_00 到 .key_data_07");
            println!("  - 元数据section: .key_meta");
        }

        "capacity" => {
            // 显示容量信息
            let store = KeyStore::new()?;
            println!("总容量: {} 字节", store.capacity());
        }

        _ => {
            print_usage(&args[0]);
        }
    }

    Ok(())
}

fn print_usage(program: &str) {
    println!("Self Crypto Key - 自修改密钥存储示例\n");
    println!("用法:");
    println!(
        "  {} init                    - 初始化并生成随机密钥",
        program
    );
    println!("  {} show                    - 显示当前密钥", program);
    println!(
        "  {} show-bytes              - 显示当前密钥(bytes)",
        program
    );
    println!("  {} update <密钥>           - 更新为指定密钥", program);
    println!(
        "  {} update-bytes <hex>      - 更新为指定bytes(hex)",
        program
    );
    println!("  {} random [长度]           - 生成并设置随机密钥", program);
    println!(
        "  {} random-bytes [长度]     - 生成并设置随机bytes",
        program
    );
    println!("  {} info                    - 显示密钥存储信息", program);
    println!("  {} capacity                - 显示总容量", program);
    println!();
    println!("示例:");
    println!("  {} init", program);
    println!("  {} show", program);
    println!("  {} update my-secret-key-123", program);
    println!("  {} update-bytes 48656c6c6f", program);
    println!("  {} random 64", program);
    println!("  {} random-bytes 128", program);
}
