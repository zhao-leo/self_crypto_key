//! 密钥存储核心实现

use crate::crypto::{decrypt_shard, derive_key_from_section, encrypt_shard};
use crate::error::{Error, Result};
use crate::metadata::KeyMetadata;
use object::{Object, ObjectSection};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;

// 引入编译时生成的加密常量
include!(concat!(env!("OUT_DIR"), "/crypto_constants.rs"));

/// 密钥存储管理器
///
/// 提供密钥的读取、更新等操作，支持任意长度的bytes数据
pub struct KeyStore {
    /// 当前可执行文件的路径
    exe_path: PathBuf,
    /// 密钥元数据
    metadata: KeyMetadata,
}

impl KeyStore {
    /// 元数据section的名称（固定）
    const METADATA_SECTION: &'static str = ".key_meta";

    /// 用于派生加密密钥的代码段（.text段不会被密钥更新修改）
    const DERIVE_SECTION: &'static str = ".text";

    /// 创建新的KeyStore实例
    ///
    /// # 返回
    ///
    /// 成功返回KeyStore实例，失败返回Error
    ///
    /// # 注意
    ///
    /// 首次使用时会自动生成配置，在第一次update时写入元数据
    pub fn new() -> Result<Self> {
        let exe_path = env::current_exe()?;

        let mut file = File::open(&exe_path)?;
        let mut binary_data = Vec::new();
        file.read_to_end(&mut binary_data)?;
        drop(file);

        // 尝试从二进制中读取现有元数据
        let metadata = Self::read_metadata(&binary_data).unwrap_or_else(|_| {
            // 如果没有元数据，生成新的配置（首次使用时会在update时写入）
            KeyMetadata::generate()
        });

        metadata.validate()?;

        Ok(Self { exe_path, metadata })
    }

    /// 更新密钥（bytes版本）
    ///
    /// 将新密钥加密后写入二进制文件，支持任意长度的数据
    ///
    /// # 参数
    ///
    /// * `new_key` - 新的密钥数据（bytes）
    ///
    /// # 返回
    ///
    /// 成功返回Ok(())，失败返回Error
    ///
    /// # 示例
    ///
    /// ```no_run
    /// # use self_crypto_key::KeyStore;
    /// let mut store = KeyStore::new()?;
    /// store.update_bytes(b"my-secret-key")?;
    /// # Ok::<(), self_crypto_key::Error>(())
    /// ```
    pub fn update_bytes(&mut self, new_key: &[u8]) -> Result<()> {
        // 读取二进制文件
        let mut binary_data = fs::read(&self.exe_path)?;

        // 首次使用时，写入元数据JSON
        let needs_metadata_init = Self::read_metadata(&binary_data).is_err();
        if needs_metadata_init {
            self.write_metadata_to_binary(&mut binary_data)?;
        }

        // 获取总容量
        let total_capacity = self.metadata.total_capacity();

        // 检查密钥长度是否超出容量
        if new_key.len() > total_capacity {
            return Err(Error::Config(format!(
                "密钥长度({})超出总容量({}), 请考虑重新编译以增加容量",
                new_key.len(),
                total_capacity
            )));
        }

        // 如果密钥长度小于总容量，填充零字节
        let mut padded_key = new_key.to_vec();
        padded_key.resize(total_capacity, 0);

        // 分片并加密
        let mut offset_in_key = 0;
        for (i, &shard_size) in self.metadata.shard_sizes.iter().enumerate() {
            let shard_data = &padded_key[offset_in_key..offset_in_key + shard_size];
            offset_in_key += shard_size;

            // 找到对应的section
            let section_name = &self.metadata.shard_names[i];
            let (section_offset, section_size) = Self::find_section(&binary_data, section_name)?;

            if section_size < shard_size {
                return Err(Error::SizeMismatch {
                    expected: shard_size,
                    actual: section_size,
                });
            }

            // 从.text段派生加密密钥
            let derive_key =
                derive_key_from_section(&binary_data, Self::DERIVE_SECTION, shard_size)?;

            // 使用编译时生成的随机种子偏移量
            let shard_seed = SHARD_SEED_OFFSETS[i % SHARD_SEED_OFFSETS.len()];

            // 加密：混淆 -> 异或
            let encrypted =
                encrypt_shard(shard_data, &derive_key, shard_seed.wrapping_add(i as u8));

            // 写入二进制数据
            binary_data[section_offset..section_offset + shard_size].copy_from_slice(&encrypted);
        }

        // 更新元数据中的实际密钥长度（存储在元数据section的前8个字节）
        let (meta_offset, _) = Self::find_section(&binary_data, Self::METADATA_SECTION)?;
        let key_len_bytes = (new_key.len() as u64).to_le_bytes();
        binary_data[meta_offset..meta_offset + 8].copy_from_slice(&key_len_bytes);

        // 原子写入
        Self::atomic_write(&self.exe_path, &binary_data)?;

        Ok(())
    }

    /// 更新密钥（字符串版本）
    ///
    /// 便捷方法，用于更新字符串类型的密钥
    ///
    /// # 参数
    ///
    /// * `new_key` - 新的密钥字符串
    ///
    /// # 返回
    ///
    /// 成功返回Ok(())，失败返回Error
    ///
    /// # 示例
    ///
    /// ```no_run
    /// # use self_crypto_key::KeyStore;
    /// let mut store = KeyStore::new()?;
    /// store.update("my-secret-key")?;
    /// # Ok::<(), self_crypto_key::Error>(())
    /// ```
    pub fn update(&mut self, new_key: &str) -> Result<()> {
        self.update_bytes(new_key.as_bytes())
    }

    /// 读取当前密钥（bytes版本）
    ///
    /// 从二进制文件中读取并解密密钥，返回原始bytes
    ///
    /// # 返回
    ///
    /// 成功返回密钥的bytes，失败返回Error
    ///
    /// # 示例
    ///
    /// ```no_run
    /// # use self_crypto_key::KeyStore;
    /// let store = KeyStore::new()?;
    /// let key_bytes = store.read_bytes()?;
    /// # Ok::<(), self_crypto_key::Error>(())
    /// ```
    pub fn read_bytes(&self) -> Result<Vec<u8>> {
        let binary_data = fs::read(&self.exe_path)?;

        // 读取实际密钥长度
        let (meta_offset, _) = Self::find_section(&binary_data, Self::METADATA_SECTION)?;
        let key_len_bytes = &binary_data[meta_offset..meta_offset + 8];
        let actual_key_len = u64::from_le_bytes([
            key_len_bytes[0],
            key_len_bytes[1],
            key_len_bytes[2],
            key_len_bytes[3],
            key_len_bytes[4],
            key_len_bytes[5],
            key_len_bytes[6],
            key_len_bytes[7],
        ]) as usize;

        // 如果密钥长度为0，返回空vec
        if actual_key_len == 0 {
            return Ok(Vec::new());
        }

        let total_capacity = self.metadata.total_capacity();
        if actual_key_len > total_capacity {
            return Err(Error::Config(format!(
                "存储的密钥长度异常: {} > {}",
                actual_key_len, total_capacity
            )));
        }

        // 读取并解密所有分片
        let mut decrypted_bytes = Vec::new();
        let mut bytes_needed = actual_key_len;

        for (i, &shard_size) in self.metadata.shard_sizes.iter().enumerate() {
            if bytes_needed == 0 {
                break;
            }

            let section_name = &self.metadata.shard_names[i];
            let (section_offset, section_size) = Self::find_section(&binary_data, section_name)?;

            if section_size < shard_size {
                return Err(Error::SizeMismatch {
                    expected: shard_size,
                    actual: section_size,
                });
            }

            let encrypted_data = &binary_data[section_offset..section_offset + shard_size];

            // 从.text段派生解密密钥
            let derive_key =
                derive_key_from_section(&binary_data, Self::DERIVE_SECTION, shard_size)?;

            // 使用编译时生成的随机种子偏移量（必须与加密时相同）
            let shard_seed = SHARD_SEED_OFFSETS[i % SHARD_SEED_OFFSETS.len()];

            // 解密：异或 -> 反混淆
            let decrypted = decrypt_shard(
                encrypted_data,
                &derive_key,
                shard_seed.wrapping_add(i as u8),
            );

            // 只取需要的字节数
            let bytes_to_take = bytes_needed.min(decrypted.len());
            decrypted_bytes.extend(&decrypted[..bytes_to_take]);
            bytes_needed -= bytes_to_take;
        }

        Ok(decrypted_bytes)
    }

    /// 读取当前密钥（字符串版本）
    ///
    /// 便捷方法，尝试将密钥解析为UTF-8字符串
    ///
    /// # 返回
    ///
    /// 成功返回密钥字符串，失败返回Error
    ///
    /// # 注意
    ///
    /// 如果密钥不是有效的UTF-8，将返回错误。对于二进制密钥，请使用`read_bytes()`
    ///
    /// # 示例
    ///
    /// ```no_run
    /// # use self_crypto_key::KeyStore;
    /// let store = KeyStore::new()?;
    /// let key = store.read()?;
    /// println!("密钥: {}", key);
    /// # Ok::<(), self_crypto_key::Error>(())
    /// ```
    pub fn read(&self) -> Result<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|e| Error::Parse(format!("密钥不是有效的UTF-8: {}", e)))
    }

    /// 获取密钥存储的总容量
    ///
    /// # 返回
    ///
    /// 总容量（字节）
    pub fn capacity(&self) -> usize {
        self.metadata.total_capacity()
    }

    /// 生成随机密钥字符串
    ///
    /// # 参数
    ///
    /// * `length` - 密钥长度（字符数）
    ///
    /// # 返回
    ///
    /// 随机生成的可打印ASCII字符串（字符范围 33-126）
    pub fn generate_random_key(length: usize) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| rng.gen_range(33..=126) as u8 as char)
            .collect()
    }

    /// 生成随机密钥bytes
    ///
    /// # 参数
    ///
    /// * `length` - 密钥长度（字节数）
    ///
    /// # 返回
    ///
    /// 随机生成的bytes
    pub fn generate_random_bytes(length: usize) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..length).map(|_| rng.gen()).collect()
    }

    /// 从二进制数据中读取元数据
    fn read_metadata(binary_data: &[u8]) -> Result<KeyMetadata> {
        let (offset, size) = Self::find_section(binary_data, Self::METADATA_SECTION)?;

        if size < 8 {
            return Err(Error::Config(format!("元数据section太小: {} < 8", size)));
        }

        // 跳过前8个字节（密钥长度），读取JSON元数据
        let metadata_bytes = &binary_data[offset + 8..offset + size];

        KeyMetadata::from_bytes(metadata_bytes)
    }

    /// 将元数据写入二进制数据的.key_meta section
    fn write_metadata_to_binary(&self, binary_data: &mut Vec<u8>) -> Result<()> {
        let (meta_offset, meta_size) = Self::find_section(binary_data, Self::METADATA_SECTION)?;

        // 序列化元数据为JSON
        let json_bytes = self.metadata.to_bytes()?;

        // 检查空间是否足够（前8字节留给密钥长度）
        if json_bytes.len() + 8 > meta_size {
            return Err(Error::Config(format!(
                "元数据section空间不足: {} + 8 > {}",
                json_bytes.len(),
                meta_size
            )));
        }

        // 写入JSON（从偏移8开始，前8字节保留给密钥长度）
        binary_data[meta_offset + 8..meta_offset + 8 + json_bytes.len()]
            .copy_from_slice(&json_bytes);

        Ok(())
    }

    /// 查找section的文件偏移和大小
    fn find_section(binary_data: &[u8], section_name: &str) -> Result<(usize, usize)> {
        let obj_file = object::File::parse(binary_data)
            .map_err(|e| Error::Parse(format!("无法解析二进制格式: {}", e)))?;

        for section in obj_file.sections() {
            if let Ok(name) = section.name() {
                if name == section_name {
                    let (offset, size) = section.file_range().ok_or_else(|| {
                        Error::Parse(format!("无法获取section {}的文件偏移", section_name))
                    })?;
                    return Ok((offset as usize, size as usize));
                }
            }
        }

        Err(Error::SectionNotFound(section_name.to_string()))
    }

    /// 原子写入文件（使用临时文件 + rename）
    fn atomic_write(path: &PathBuf, data: &[u8]) -> Result<()> {
        let temp_path = path.with_extension("tmp");

        // 写入临时文件
        fs::write(&temp_path, data)?;

        // 复制权限
        #[cfg(unix)]
        {
            let metadata = fs::metadata(path)?;
            let permissions = metadata.permissions();
            fs::set_permissions(&temp_path, permissions)?;
        }

        // 原子重命名
        fs::rename(&temp_path, path)?;

        Ok(())
    }
}
