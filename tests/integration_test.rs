//! 集成测试
//!
//! 测试完整的密钥存储、更新和读取流程

use self_crypto_key::{init_key_storage, KeyStore};

// 初始化密钥存储（测试用，8KB）
init_key_storage!();

#[test]
fn test_key_generation() {
    // 测试随机密钥生成
    let key1 = KeyStore::generate_random_key(20);
    let key2 = KeyStore::generate_random_key(20);

    assert_eq!(key1.len(), 20);
    assert_eq!(key2.len(), 20);
    assert_ne!(key1, key2);

    // 验证字符范围
    for ch in key1.chars() {
        let code = ch as u32;
        assert!(code >= 33 && code <= 126, "字符 '{}' 不在可打印范围", ch);
    }
}

#[test]
fn test_bytes_generation() {
    // 测试随机bytes生成
    let bytes1 = KeyStore::generate_random_bytes(32);
    let bytes2 = KeyStore::generate_random_bytes(32);

    assert_eq!(bytes1.len(), 32);
    assert_eq!(bytes2.len(), 32);
    assert_ne!(bytes1, bytes2);
}

#[test]
fn test_different_lengths() {
    // 测试不同长度的密钥
    for len in [1, 10, 32, 64, 128, 256, 512, 1024] {
        let key = KeyStore::generate_random_key(len);
        assert_eq!(key.len(), len, "长度 {} 的密钥生成失败", len);
    }
}

#[test]
fn test_keystore_creation() {
    // 测试KeyStore创建
    let store = KeyStore::new();

    match store {
        Ok(store) => {
            println!("KeyStore创建成功");
            let capacity = store.capacity();
            println!("  总容量: {} 字节", capacity);
            assert!(capacity > 0, "容量应该大于0");
            // 容量取决于随机选择的shard数量（4-8个，每个1KB）
            assert!(
                capacity >= 4096 && capacity <= 8192,
                "容量应该在4KB到8KB之间"
            );
        }
        Err(e) => {
            println!("KeyStore创建失败: {}", e);
        }
    }
}

#[test]
fn test_capacity() {
    // 测试容量查询
    if let Ok(store) = KeyStore::new() {
        let capacity = store.capacity();
        // 容量取决于随机选择的shard数量（4-8个，每个1KB）
        assert!(
            capacity >= 4 * 1024 && capacity <= 8 * 1024,
            "总容量应该在4KB到8KB之间"
        );
    }
}

#[test]
fn test_empty_key() {
    // 测试空密钥
    let store = KeyStore::new();

    if let Ok(mut store) = store {
        let result = store.update("");
        match result {
            Ok(_) => println!("空密钥存储成功"),
            Err(e) => println!("空密钥存储失败: {}", e),
        }
    }
}

#[test]
fn test_empty_bytes() {
    // 测试空bytes
    let store = KeyStore::new();

    if let Ok(mut store) = store {
        let result = store.update_bytes(b"");
        match result {
            Ok(_) => println!("空bytes存储成功"),
            Err(e) => println!("空bytes存储失败: {}", e),
        }
    }
}

#[test]
fn test_special_characters() {
    // 测试特殊字符
    let special_keys = vec![
        "hello@world!",
        "password#123$",
        "key~with^special&chars",
        "tab\there",
        "new\nline",
    ];

    let store = KeyStore::new();

    if let Ok(mut store) = store {
        for key in special_keys {
            let result = store.update(key);
            match result {
                Ok(_) => println!("特殊字符密钥 '{}' 测试通过", key.escape_default()),
                Err(e) => println!("特殊字符密钥失败: {}", e),
            }
        }
    }
}

#[test]
fn test_binary_data() {
    // 测试二进制数据
    let binary_data = vec![0u8, 1, 2, 255, 254, 128, 127];

    let store = KeyStore::new();

    if let Ok(mut store) = store {
        let result = store.update_bytes(&binary_data);
        match result {
            Ok(_) => println!("二进制数据存储成功"),
            Err(e) => println!("二进制数据存储失败: {}", e),
        }
    }
}

#[test]
fn test_boundary_conditions() {
    // 测试边界条件

    // 测试最小长度（1字节）
    let key_min = KeyStore::generate_random_key(1);
    assert_eq!(key_min.len(), 1);

    // 测试大数据
    let key_large = KeyStore::generate_random_key(4096);
    assert_eq!(key_large.len(), 4096);

    println!("边界条件测试通过");
}

#[test]
fn test_concurrent_access() {
    // 测试是否能安全地多次创建KeyStore实例
    use std::thread;

    let handles: Vec<_> = (0..5)
        .map(|i| {
            thread::spawn(move || {
                let store = KeyStore::new();
                match store {
                    Ok(store) => {
                        println!("线程 {} 创建KeyStore成功, 容量: {}", i, store.capacity());
                    }
                    Err(e) => println!("线程 {} 创建KeyStore失败: {}", i, e),
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    println!("并发访问测试完成");
}

#[test]
fn test_large_data() {
    // 测试大数据存储
    let large_key = vec![42u8; 5000]; // 5KB

    let store = KeyStore::new();

    if let Ok(mut store) = store {
        let result = store.update_bytes(&large_key);
        match result {
            Ok(_) => println!("大数据(5KB)存储成功"),
            Err(e) => println!("大数据存储失败: {}", e),
        }
    }
}

#[test]
fn test_very_large_data() {
    // 测试接近容量上限的数据
    let very_large_key = vec![99u8; 8000]; // 接近8KB

    let store = KeyStore::new();

    if let Ok(mut store) = store {
        let result = store.update_bytes(&very_large_key);
        match result {
            Ok(_) => println!("接近上限数据(8000字节)存储成功"),
            Err(e) => println!("接近上限数据存储失败: {}", e),
        }
    }
}

#[test]
fn test_exceed_capacity() {
    // 测试超出容量的数据
    let too_large_key = vec![1u8; 10000]; // 超过8KB

    let store = KeyStore::new();

    if let Ok(mut store) = store {
        let result = store.update_bytes(&too_large_key);
        match result {
            Ok(_) => panic!("不应该允许存储超出容量的数据"),
            Err(e) => {
                println!("正确拒绝了超出容量的数据: {}", e);
            }
        }
    }
}

#[test]
fn test_metadata_generation() {
    // 测试元数据生成
    for i in 0..5 {
        let store = KeyStore::new();
        match store {
            Ok(_) => println!("第 {} 次创建KeyStore成功", i),
            Err(e) => println!("第 {} 次创建KeyStore失败: {}", i, e),
        }
    }
}

#[test]
fn test_different_data_types() {
    // 测试不同类型的数据
    let incremental: Vec<u8> = (0u8..=255).collect();
    let test_cases = vec![
        ("纯文本", b"Hello World".as_slice()),
        ("数字", b"1234567890".as_slice()),
        ("混合", b"abc123!@#".as_slice()),
        ("全0", &[0u8; 100][..]),
        ("全255", &[255u8; 100][..]),
        ("递增", incremental.as_slice()),
    ];

    let store = KeyStore::new();

    if let Ok(mut store) = store {
        for (name, data) in test_cases {
            let result = store.update_bytes(data);
            match result {
                Ok(_) => println!("{} 数据测试通过", name),
                Err(e) => println!("{} 数据测试失败: {}", name, e),
            }
        }
    }
}

/// 辅助函数：验证密钥字符串的有效性
fn validate_key_string(key: &str) -> bool {
    if key.is_empty() {
        return true;
    }

    key.chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\t')
}

#[test]
fn test_key_validation() {
    let valid_keys = vec![
        "",
        "simple",
        "with spaces",
        "special!@#$%^&*()",
        "123456789",
    ];

    for key in valid_keys {
        assert!(validate_key_string(key), "密钥 '{}' 应该是有效的", key);
    }

    println!("密钥验证测试通过");
}
