//! 加密和混淆相关函数

use crate::error::{Error, Result};
use object::{Object, ObjectSection};
use sha2::{Digest, Sha256};

/// 异或加密/解密
///
/// 使用密钥对数据进行异或运算，加密和解密使用相同的函数
///
/// # 参数
///
/// * `data` - 要加密/解密的数据
/// * `key` - 密钥（会循环使用）
///
/// # 返回
///
/// 加密/解密后的数据
pub fn xor_cipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// 混淆数据
///
/// 应用位反转和字节运算来混淆数据，使其难以直接识别
///
/// # 参数
///
/// * `data` - 要混淆的数据
/// * `seed` - 混淆种子（不同的种子产生不同的混淆结果）
///
/// # 返回
///
/// 混淆后的数据
pub fn obfuscate(data: &[u8], seed: u8) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| {
            // 位反转 + 加上种子和位置偏移
            (!b).wrapping_add(seed).wrapping_add(i as u8)
        })
        .collect()
}

/// 反混淆数据
///
/// 将混淆后的数据恢复为原始数据
///
/// # 参数
///
/// * `data` - 混淆后的数据
/// * `seed` - 混淆时使用的种子（必须相同）
///
/// # 返回
///
/// 恢复后的原始数据
pub fn deobfuscate(data: &[u8], seed: u8) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| {
            // 减去位置偏移和种子 + 位反转
            !(b.wrapping_sub(i as u8).wrapping_sub(seed))
        })
        .collect()
}

/// 从指定section计算SHA256哈希，用于派生加密密钥
///
/// # 参数
///
/// * `binary_data` - 完整的二进制文件数据
/// * `section_name` - 要计算哈希的section名称
/// * `key_len` - 需要的密钥长度
///
/// # 返回
///
/// 派生的密钥（取哈希值的前key_len字节）
pub fn derive_key_from_section(
    binary_data: &[u8],
    section_name: &str,
    key_len: usize,
) -> Result<Vec<u8>> {
    let obj_file = object::File::parse(binary_data)
        .map_err(|e| Error::Parse(format!("无法解析二进制格式: {}", e)))?;

    for section in obj_file.sections() {
        if let Ok(name) = section.name() {
            if name == section_name {
                if let Ok(data) = section.data() {
                    // 计算section数据的SHA256哈希
                    let mut hasher = Sha256::new();
                    hasher.update(data);
                    let hash = hasher.finalize();

                    // 返回前key_len字节（最多32字节）
                    return Ok(hash[..key_len.min(32)].to_vec());
                }
            }
        }
    }

    Err(Error::SectionNotFound(section_name.to_string()))
}

/// 加密数据片段
///
/// 完整的加密流程：混淆 -> 异或加密
///
/// # 参数
///
/// * `data` - 要加密的数据
/// * `derive_key` - 派生的加密密钥
/// * `seed` - 混淆种子
///
/// # 返回
///
/// 加密后的数据
pub fn encrypt_shard(data: &[u8], derive_key: &[u8], seed: u8) -> Vec<u8> {
    // 步骤1: 混淆
    let obfuscated = obfuscate(data, seed);

    // 步骤2: 异或加密
    xor_cipher(&obfuscated, derive_key)
}

/// 解密数据片段
///
/// 完整的解密流程：异或解密 -> 反混淆
///
/// # 参数
///
/// * `encrypted_data` - 加密后的数据
/// * `derive_key` - 派生的加密密钥（必须与加密时相同）
/// * `seed` - 混淆种子（必须与加密时相同）
///
/// # 返回
///
/// 解密后的原始数据
pub fn decrypt_shard(encrypted_data: &[u8], derive_key: &[u8], seed: u8) -> Vec<u8> {
    // 步骤1: 异或解密
    let xor_decrypted = xor_cipher(encrypted_data, derive_key);

    // 步骤2: 反混淆
    deobfuscate(&xor_decrypted, seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_cipher() {
        let data = b"hello world";
        let key = b"secret";

        let encrypted = xor_cipher(data, key);
        assert_ne!(data, encrypted.as_slice());

        let decrypted = xor_cipher(&encrypted, key);
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_obfuscate() {
        let data = b"test data 12345";
        let seed = 42;

        let obfuscated = obfuscate(data, seed);
        assert_ne!(data, obfuscated.as_slice());

        let deobfuscated = deobfuscate(&obfuscated, seed);
        assert_eq!(data, deobfuscated.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_shard() {
        let original = b"my secret key";
        let derive_key = b"derived_key_from_hash";
        let seed = 123;

        let encrypted = encrypt_shard(original, derive_key, seed);
        assert_ne!(original, encrypted.as_slice());

        let decrypted = decrypt_shard(&encrypted, derive_key, seed);
        assert_eq!(original, decrypted.as_slice());
    }

    #[test]
    fn test_different_seeds_produce_different_results() {
        let data = b"same data";
        let key = b"same key";

        let encrypted1 = encrypt_shard(data, key, 1);
        let encrypted2 = encrypt_shard(data, key, 2);

        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let key = b"key";
        let seed = 1;

        let encrypted = encrypt_shard(data, key, seed);
        assert_eq!(encrypted.len(), 0);

        let decrypted = decrypt_shard(&encrypted, key, seed);
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_large_data() {
        let data = vec![42u8; 10000];
        let key = b"test_key";
        let seed = 99;

        let encrypted = encrypt_shard(&data, key, seed);
        assert_eq!(encrypted.len(), data.len());

        let decrypted = decrypt_shard(&encrypted, key, seed);
        assert_eq!(data, decrypted);
    }
}
