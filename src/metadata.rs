//! 密钥存储的元数据定义和操作

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// 密钥存储的元数据配置
///
/// 描述密钥的分片信息和加密配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// 分片数量（4-8个）
    pub num_shards: usize,

    /// 每个分片的大小（字节）
    pub shard_sizes: Vec<usize>,

    /// 每个分片对应的section名称（格式：.key_data_xx）
    pub shard_names: Vec<String>,

    /// 版本信息
    pub version: u32,
}

impl KeyMetadata {
    /// 当前版本号
    pub const VERSION: u32 = 1;

    /// 预定义的shard section名称（固定8个）
    pub const SHARD_NAMES: [&'static str; 8] = [
        ".key_data_00",
        ".key_data_01",
        ".key_data_02",
        ".key_data_03",
        ".key_data_04",
        ".key_data_05",
        ".key_data_06",
        ".key_data_07",
    ];

    /// 每个shard的标准大小（1KB）
    pub const SHARD_SIZE: usize = 1024;

    /// 生成新的元数据配置
    ///
    /// 随机决定使用4-8个分片
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // 随机选择4-8个分片
        let num_shards = rng.gen_range(4..=8);

        // 使用预定义的section名称
        use rand::seq::SliceRandom;
        let mut available_indices: Vec<usize> = (0..8).collect();
        available_indices.shuffle(&mut rng);

        let shard_names: Vec<String> = available_indices
            .iter()
            .take(num_shards)
            .map(|&i| Self::SHARD_NAMES[i].to_string())
            .collect();

        let shard_sizes = vec![Self::SHARD_SIZE; num_shards];

        Self {
            num_shards,
            shard_sizes,
            shard_names,
            version: Self::VERSION,
        }
    }

    /// 从JSON字节反序列化
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // 查找JSON的开始和结束位置
        let json_start = data
            .iter()
            .position(|&b| b == b'{')
            .ok_or_else(|| Error::Parse("未找到元数据JSON开始标记".to_string()))?;

        let json_end = data
            .iter()
            .rposition(|&b| b == b'}')
            .ok_or_else(|| Error::Parse("未找到元数据JSON结束标记".to_string()))?;

        if json_start > json_end {
            return Err(Error::Parse("无效的JSON范围".to_string()));
        }

        let json_bytes = &data[json_start..=json_end];
        serde_json::from_slice(json_bytes).map_err(Error::from)
    }

    /// 序列化为JSON字节
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::from)
    }

    /// 计算总容量（所有shard的大小之和）
    pub fn total_capacity(&self) -> usize {
        self.shard_sizes.iter().sum()
    }

    /// 验证元数据的有效性
    pub fn validate(&self) -> Result<()> {
        if self.num_shards == 0 {
            return Err(Error::Config("分片数量不能为0".to_string()));
        }

        if self.num_shards > 8 {
            return Err(Error::Config(format!(
                "分片数量不能超过8: {}",
                self.num_shards
            )));
        }

        if self.shard_sizes.len() != self.num_shards {
            return Err(Error::Config(format!(
                "分片大小数量({})与分片数量({})不匹配",
                self.shard_sizes.len(),
                self.num_shards
            )));
        }

        if self.shard_names.len() != self.num_shards {
            return Err(Error::Config(format!(
                "分片名称数量({})与分片数量({})不匹配",
                self.shard_names.len(),
                self.num_shards
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_generation() {
        let meta = KeyMetadata::generate();
        assert!(meta.num_shards >= 4 && meta.num_shards <= 8);
        assert_eq!(meta.shard_sizes.len(), meta.num_shards);
        assert_eq!(meta.shard_names.len(), meta.num_shards);
        meta.validate().unwrap();
    }

    #[test]
    fn test_metadata_serialization() {
        let meta = KeyMetadata::generate();
        let bytes = meta.to_bytes().unwrap();
        let meta2 = KeyMetadata::from_bytes(&bytes).unwrap();

        assert_eq!(meta.num_shards, meta2.num_shards);
        assert_eq!(meta.shard_sizes, meta2.shard_sizes);
        assert_eq!(meta.shard_names, meta2.shard_names);
    }

    #[test]
    fn test_total_capacity() {
        let meta = KeyMetadata::generate();
        let expected = meta.shard_sizes.iter().sum::<usize>();
        assert_eq!(meta.total_capacity(), expected);
    }
}
