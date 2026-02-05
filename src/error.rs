//! 错误类型定义

use std::fmt;

/// 库的错误类型
#[derive(Debug)]
pub enum Error {
    /// IO错误
    Io(std::io::Error),

    /// 二进制解析错误
    Parse(String),

    /// 加密/解密错误
    Crypto(String),

    /// 配置错误
    Config(String),

    /// Section未找到
    SectionNotFound(String),

    /// 数据大小不匹配
    SizeMismatch { expected: usize, actual: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO错误: {}", e),
            Error::Parse(e) => write!(f, "解析错误: {}", e),
            Error::Crypto(e) => write!(f, "加密错误: {}", e),
            Error::Config(e) => write!(f, "配置错误: {}", e),
            Error::SectionNotFound(name) => write!(f, "未找到section: {}", name),
            Error::SizeMismatch { expected, actual } => {
                write!(f, "大小不匹配: 期望 {}, 实际 {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Parse(format!("JSON错误: {}", e))
    }
}

/// 结果类型别名
pub type Result<T> = std::result::Result<T, Error>;
