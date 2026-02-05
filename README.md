# Self Crypto Key

一个用于在二进制文件中存储和自修改加密密钥的 Rust 库。

## 安全声明

**本库提供的是"提高破解难度"的方案，而非绝对安全。**

在开源环境下，拥有完整二进制和源代码的攻击者理论上可以提取密钥。这是软件保护的根本性限制。

对于高安全需求场景，建议考虑：
- 硬件安全模块（TPM, Intel SGX, ARM TrustZone）
- 服务器端验证
- 用户密码派生

## 快速开始

### 安装

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
self_crypto_key = "0.1"
```

### 基本使用

```rust
use self_crypto_key::{init_key_storage, KeyStore};

// 1. 在程序开头初始化密钥存储（最大 256 字节）
init_key_storage!(256);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 2. 创建 KeyStore 实例
    let mut store = KeyStore::new(256)?;
    
    // 3. 生成并存储随机密钥
    let random_key = KeyStore::generate_random_key(32);
    store.update(&random_key)?;
    println!("密钥已设置: {}", random_key);
    
    // 4. 读取密钥
    let key = store.read()?;
    println!("当前密钥: {}", key);
    
    Ok(())
}
```

### 运行示例

```bash
# 构建示例
cargo build --release --example basic_usage

# 初始化密钥
./target/release/examples/basic_usage init

# 查看密钥
./target/release/examples/basic_usage show

# 更新密钥
./target/release/examples/basic_usage update "my-secret-key"

# 生成随机密钥（64字节）
./target/release/examples/basic_usage random 64
```

## 工作原理

### 1. 密钥分片存储

密钥被随机分成 3-8 个片段，每个片段存储在独立的 ELF section 中：

```
密钥: "my-secret-key-12345678"
 ↓
片段 0: "my-se"  → .data_847
片段 1: "cret-"  → .rodata_392
片段 2: "key-1"  → .bss_615
片段 3: "2345678" → .init_928
```

### 2. 基于代码段的加密

每个片段使用程序不同代码段的哈希值加密：

```rust
// 片段 0 使用 .text 段的哈希
derive_key = SHA256(.text)[0..shard_size]
encrypted_shard_0 = obfuscate(shard_0) XOR derive_key

// 片段 1 使用 .rodata 段的哈希
derive_key = SHA256(.rodata)[0..shard_size]
encrypted_shard_1 = obfuscate(shard_1) XOR derive_key

// 以此类推...
```

### 3. 多层混淆

```rust
原始数据
  ↓
位反转 + 字节运算（基于位置和种子）
  ↓
异或加密（使用派生密钥）
  ↓
存储到二进制
```

### 4. 自修改机制

程序通过以下步骤实现自修改：

1. 读取自身二进制文件到内存
2. 解析 ELF 格式，定位密钥 sections
3. 修改内存中的密钥数据
4. 写入临时文件
5. 原子重命名替换原文件
