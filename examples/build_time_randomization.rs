//! 展示编译时随机化加密特性
//!
//! 这个示例展示了如何使用 build.rs 生成的编译时随机常量来增强密钥加密。
//! 每次编译时，加密算法都会使用不同的随机参数，使得即使攻击者拥有源代码，
//! 也需要针对每个编译后的二进制进行单独分析。

use self_crypto_key::{init_key_storage, KeyStore};
use std::error::Error;

// 初始化密钥存储空间（8KB 容量）
init_key_storage!();

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== 编译时随机化加密演示 ===\n");

    // 创建密钥存储实例
    let mut store = KeyStore::new()?;

    println!("密钥存储容量: {} 字节", store.capacity());
    println!();

    // 演示1：字符串密钥
    let test_key = "my-super-secret-api-key-2024";
    println!("原始密钥: {}", test_key);

    store.update(test_key)?;
    println!("密钥已加密并存储");

    let retrieved_key = store.read()?;
    println!("读取的密钥: {}", retrieved_key);
    assert_eq!(test_key, retrieved_key);
    println!("验证成功\n");

    // 演示2：二进制数据
    let binary_data = vec![0x42, 0xFF, 0x00, 0xAB, 0xCD, 0xEF, 0x12, 0x34];
    println!("原始数据: {:02X?}", binary_data);

    store.update_bytes(&binary_data)?;

    let retrieved_data = store.read_bytes()?;
    println!("读取的数据: {:02X?}", retrieved_data);
    assert_eq!(binary_data, retrieved_data);

    // 演示3：长密钥
    let long_key = KeyStore::generate_random_bytes(1024);
    println!("生成随机密钥: {} 字节", long_key.len());

    store.update_bytes(&long_key)?;
    println!("长密钥已加密并存储");

    let retrieved_long = store.read_bytes()?;
    assert_eq!(long_key.len(), retrieved_long.len());
    assert_eq!(long_key, retrieved_long);
    println!("验证成功 ({} 字节)\n", retrieved_long.len());

    // 演示4：最大容量测试
    let max_capacity = store.capacity();
    let max_key = KeyStore::generate_random_bytes(max_capacity);
    println!("生成最大容量密钥: {} 字节", max_key.len());

    store.update_bytes(&max_key)?;
    println!("最大容量密钥已加密并存储");

    let retrieved_max = store.read_bytes()?;
    assert_eq!(max_key, retrieved_max);
    println!("验证成功 ({} 字节)\n", retrieved_max.len());

    // 性能测试
    println!("--- 性能测试 ---");
    let test_data = KeyStore::generate_random_bytes(4096);
    let iterations = 100;

    let start = std::time::Instant::now();
    for _ in 0..iterations {
        store.update_bytes(&test_data)?;
    }
    let elapsed = start.elapsed();

    println!("{} 次写入操作 (4KB 数据)", iterations);
    println!("   总耗时: {:?}", elapsed);
    println!("   平均: {:.2?} 每次", elapsed / iterations);
    println!();

    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = store.read_bytes()?;
    }
    let elapsed = start.elapsed();

    println!("{} 次读取操作 (4KB 数据)", iterations);
    println!("   总耗时: {:?}", elapsed);
    println!("   平均: {:.2?} 每次", elapsed / iterations);
    println!();

    Ok(())
}
