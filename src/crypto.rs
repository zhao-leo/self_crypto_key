//! 加密和混淆相关函数

use crate::error::{Error, Result};
use object::{Object, ObjectSection};
use sha2::{Digest, Sha256};

// 引入编译时生成的加密常量
include!(concat!(env!("OUT_DIR"), "/crypto_constants.rs"));

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
/// 应用多层混淆技术，包括：
/// 1. 位旋转
/// 2. S-box 置换
/// 3. 编译时随机化的算术运算
/// 4. 多轮迭代
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
    let mut result: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let mut byte = b;

            // 第1层：位旋转（使用编译时常量）
            byte = byte.rotate_left(ROTATION_BITS);

            // 第2层：S-box 置换（使用编译时生成的置换表）
            byte = OBFUSCATE_TABLE[byte as usize];

            // 第3层：编译时随机化的算术混淆
            byte = byte
                .wrapping_mul(OBFUSCATE_MULTIPLIER)
                .wrapping_add(OBFUSCATE_BASE)
                .wrapping_add(seed)
                .wrapping_add(i as u8);

            // 第4层：异或掩码
            byte ^= XOR_MASK;

            byte
        })
        .collect();

    // 额外混淆轮次（编译时随机确定）
    for round in 0..EXTRA_ROUNDS {
        result = result
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                b.wrapping_add((round as u8).wrapping_mul(seed))
                    .wrapping_add(i as u8)
            })
            .collect();
    }

    result
}

/// 反混淆数据
///
/// 将混淆后的数据恢复为原始数据
/// 必须以相反的顺序撤销所有混淆层
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
    let mut result = data.to_vec();

    // 撤销额外混淆轮次（逆序）
    for round in (0..EXTRA_ROUNDS).rev() {
        result = result
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                b.wrapping_sub(i as u8)
                    .wrapping_sub((round as u8).wrapping_mul(seed))
            })
            .collect();
    }

    // 撤销主混淆层（逆序）
    result
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let mut byte = b;

            // 撤销第4层：异或掩码
            byte ^= XOR_MASK;

            // 撤销第3层：算术混淆
            byte = byte
                .wrapping_sub(i as u8)
                .wrapping_sub(seed)
                .wrapping_sub(OBFUSCATE_BASE);

            // 计算乘法逆元（对于模256）
            let inv_multiplier = mod_inverse(OBFUSCATE_MULTIPLIER);
            byte = byte.wrapping_mul(inv_multiplier);

            // 撤销第2层：S-box 置换
            byte = DEOBFUSCATE_TABLE[byte as usize];

            // 撤销第1层：位旋转
            byte = byte.rotate_right(ROTATION_BITS);

            byte
        })
        .collect()
}

/// 计算模256的乘法逆元
///
/// 使用扩展欧几里得算法
fn mod_inverse(a: u8) -> u8 {
    // 对于奇数 a，在模256下总是存在逆元
    let mut t = 0i32;
    let mut new_t = 1i32;
    let mut r = 256i32;
    let mut new_r = a as i32;

    while new_r != 0 {
        let quotient = r / new_r;
        let tmp_t = t;
        t = new_t;
        new_t = tmp_t - quotient * new_t;
        let tmp_r = r;
        r = new_r;
        new_r = tmp_r - quotient * new_r;
    }

    if t < 0 {
        t += 256;
    }

    t as u8
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
