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
