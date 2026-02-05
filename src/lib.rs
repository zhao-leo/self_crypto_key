//! # Self Crypto Key
//!
//! 一个用于在二进制文件中存储和自修改加密密钥的 Rust 库。
//!
//! ## 特性
//!
//! - **分散存储**: 密钥被分割成随机数量（4-8个）的片段，分散存储在不同的 ELF sections 中
//! - **代码段绑定**: 每个片段使用程序 .text 代码段的 SHA256 哈希值加密
//! - **多层混淆**: 应用位反转、字节置换和异或等多层混淆技术
//! - **无长度限制**: 支持任意长度的密钥（受限于编译时分配的总容量）
//! - **Bytes支持**: 同时支持字符串和二进制数据
//! - **自修改**: 程序可以在运行时修改自身二进制中的密钥数据
//!
//! ## 安全说明
//!
//! 此库提供的是**提高破解难度**的方案，而非绝对安全。在开源环境下，
//! 拥有完整二进制和源代码的攻击者理论上可以提取密钥。
//!
//! 对于高安全需求，建议考虑：
//! - 硬件安全模块 (TPM, SGX)
//! - 服务器端验证
//! - 用户密码派生
//!
//! ## 使用示例
//!
//! ```rust,no_run
//! use self_crypto_key::{init_key_storage, KeyStore};
//!
//! // 在程序开头初始化密钥存储
//! init_key_storage!();
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 创建密钥存储实例
//!     let mut store = KeyStore::new()?;
//!
//!     // 更新密钥（字符串）
//!     store.update("my-secret-key")?;
//!
//!     // 读取密钥
//!     let key = store.read()?;
//!     println!("密钥: {}", key);
//!
//!     // 使用bytes
//!     store.update_bytes(b"binary-data")?;
//!     let bytes = store.read_bytes()?;
//!
//!     Ok(())
//! }
//! ```

// 内部模块
mod crypto;
mod error;
mod key_store;
mod metadata;

// 公开导出
pub use error::{Error, Result};
pub use key_store::KeyStore;

/// 用于在编译时初始化密钥存储空间的宏
///
/// 此宏会创建多个 ELF sections 用于存储密钥数据和元数据。
/// 每个 section 的大小为 1KB，总共8个 shard sections，提供 8KB 的存储空间。
///
/// # 使用示例
///
/// ```rust
/// use self_crypto_key::init_key_storage;
///
/// // 在程序的某处声明（通常在main.rs或lib.rs的顶层）
/// init_key_storage!();
/// ```
///
/// # 注意
///
/// - 此宏只能在程序中调用一次
/// - 生成的 sections 命名为 `.key_data_00` 到 `.key_data_07`
/// - 元数据 section 命名为 `.key_meta`，大小为 4KB
/// - 总容量为 8KB（8个1KB的shards）
#[macro_export]
macro_rules! init_key_storage {
    () => {
        // 元数据section（固定名称，4KB）
        // 前8字节存储实际密钥长度，后续存储JSON元数据
        #[link_section = ".key_meta"]
        #[used]
        #[no_mangle]
        static KEY_METADATA: [u8; 4096] = [0u8; 4096];

        // 数据存储sections（8个，每个1KB）
        #[link_section = ".key_data_00"]
        #[used]
        #[no_mangle]
        static SHARD_00: [u8; 1024] = [0u8; 1024];

        #[link_section = ".key_data_01"]
        #[used]
        #[no_mangle]
        static SHARD_01: [u8; 1024] = [0u8; 1024];

        #[link_section = ".key_data_02"]
        #[used]
        #[no_mangle]
        static SHARD_02: [u8; 1024] = [0u8; 1024];

        #[link_section = ".key_data_03"]
        #[used]
        #[no_mangle]
        static SHARD_03: [u8; 1024] = [0u8; 1024];

        #[link_section = ".key_data_04"]
        #[used]
        #[no_mangle]
        static SHARD_04: [u8; 1024] = [0u8; 1024];

        #[link_section = ".key_data_05"]
        #[used]
        #[no_mangle]
        static SHARD_05: [u8; 1024] = [0u8; 1024];

        #[link_section = ".key_data_06"]
        #[used]
        #[no_mangle]
        static SHARD_06: [u8; 1024] = [0u8; 1024];

        #[link_section = ".key_data_07"]
        #[used]
        #[no_mangle]
        static SHARD_07: [u8; 1024] = [0u8; 1024];
    };
}
