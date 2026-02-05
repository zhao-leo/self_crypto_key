use std::env;
use std::fs;
use std::path::Path;

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

    // 生成编译时随机化参数，提高加密强度
    generate_crypto_constants();

    // 如果需要，可以设置重新运行的条件
    println!("cargo:rerun-if-changed=build.rs");
}

/// 生成编译时加密常量
///
/// 这些常量在每次编译时都会随机生成，使得每个二进制文件的加密方式都不同
/// 即使攻击者拥有源代码，也需要针对每个编译的二进制进行分析
fn generate_crypto_constants() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    // 使用编译时间戳作为随机种子
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut hasher = DefaultHasher::new();
    timestamp.hash(&mut hasher);
    let seed = hasher.finish();

    // 生成随机常量
    let constants = CryptoConstants::generate(seed);

    // 生成 Rust 代码文件
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("crypto_constants.rs");

    let code = format!(
        r#"// 此文件由 build.rs 自动生成
// 编译时间戳: {}
// 警告：请勿手动修改此文件

/// 编译时生成的混淆种子基数
#[allow(dead_code)]
pub const OBFUSCATE_BASE: u8 = {};

/// 编译时生成的混淆乘数
#[allow(dead_code)]
pub const OBFUSCATE_MULTIPLIER: u8 = {};

/// 编译时生成的异或掩码
#[allow(dead_code)]
pub const XOR_MASK: u8 = {};

/// 编译时生成的轮转位数
#[allow(dead_code)]
pub const ROTATION_BITS: u32 = {};

/// 编译时生成的额外混淆层数
#[allow(dead_code)]
pub const EXTRA_ROUNDS: usize = {};

/// 编译时生成的混淆表（256字节的置换表）
#[allow(dead_code)]
pub const OBFUSCATE_TABLE: [u8; 256] = [
{}
];

/// 编译时生成的反混淆表
#[allow(dead_code)]
pub const DEOBFUSCATE_TABLE: [u8; 256] = [
{}
];

/// 编译时生成的分片种子偏移量
#[allow(dead_code)]
pub const SHARD_SEED_OFFSETS: [u8; 8] = {:?};
"#,
        timestamp,
        constants.obfuscate_base,
        constants.obfuscate_multiplier,
        constants.xor_mask,
        constants.rotation_bits,
        constants.extra_rounds,
        format_table(&constants.obfuscate_table),
        format_table(&constants.deobfuscate_table),
        constants.shard_seed_offsets,
    );

    fs::write(&dest_path, code).unwrap();

    // println!("cargo:warning=已生成编译时加密常量 (种子: {})", seed);
}

/// 格式化256字节数组为可读的代码格式
fn format_table(table: &[u8; 256]) -> String {
    let mut result = String::new();
    for (i, &byte) in table.iter().enumerate() {
        if i % 16 == 0 {
            result.push_str("    ");
        }
        result.push_str(&format!("{:#04x}", byte));
        if i < 255 {
            result.push_str(", ");
        }
        if i % 16 == 15 {
            result.push('\n');
        }
    }
    result
}

/// 编译时加密常量结构
struct CryptoConstants {
    obfuscate_base: u8,
    obfuscate_multiplier: u8,
    xor_mask: u8,
    rotation_bits: u32,
    extra_rounds: usize,
    obfuscate_table: [u8; 256],
    deobfuscate_table: [u8; 256],
    shard_seed_offsets: [u8; 8],
}

impl CryptoConstants {
    /// 基于种子生成随机常量
    fn generate(seed: u64) -> Self {
        let mut rng = SimpleRng::new(seed);

        // 生成基础混淆参数
        let obfuscate_base = rng.next_u8() | 1; // 确保是奇数
        let obfuscate_multiplier = rng.next_u8() | 1; // 确保是奇数
        let xor_mask = rng.next_u8();
        let rotation_bits = (rng.next_u8() % 7) as u32 + 1; // 1-7 位
        let extra_rounds = (rng.next_u8() % 3) as usize + 1; // 1-3 轮

        // 生成置换表（S-box）
        let mut obfuscate_table = [0u8; 256];
        for i in 0..256 {
            obfuscate_table[i] = i as u8;
        }

        // Fisher-Yates 洗牌算法
        for i in (1..256).rev() {
            let j = (rng.next_u8() as usize) % (i + 1);
            obfuscate_table.swap(i, j);
        }

        // 生成反置换表
        let mut deobfuscate_table = [0u8; 256];
        for (i, &val) in obfuscate_table.iter().enumerate() {
            deobfuscate_table[val as usize] = i as u8;
        }

        // 生成分片种子偏移量
        let mut shard_seed_offsets = [0u8; 8];
        for offset in &mut shard_seed_offsets {
            *offset = rng.next_u8();
        }

        Self {
            obfuscate_base,
            obfuscate_multiplier,
            xor_mask,
            rotation_bits,
            extra_rounds,
            obfuscate_table,
            deobfuscate_table,
            shard_seed_offsets,
        }
    }
}

/// 简单的伪随机数生成器（用于build.rs，避免依赖外部crate）
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9e3779b97f4a7c15),
        }
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        self.state.wrapping_mul(0x2545f4914f6cdd1d)
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}
