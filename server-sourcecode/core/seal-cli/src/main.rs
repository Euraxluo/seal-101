// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * Seal命令行接口 (Seal CLI)
 * 
 * 本模块实现了Seal密钥管理系统的命令行界面，提供了一套完整的工具来管理
 * 与Seal密码系统交互所需的密钥和加密操作。通过此CLI，用户可以：
 * 
 * - 生成IBE密钥对
 * - 提取用户私钥
 * - 验证用户私钥
 * - 使用Seal进行加密和解密操作
 * - 解析和查看加密对象的结构
 * 
 * 该CLI是Seal密码学核心库的前端，使开发者能够在命令行环境中测试和使用
 * 所有密码功能，而无需编写额外代码。
 */

use clap::{Parser, Subcommand};
use crypto::dem::{Aes256Gcm, Hmac256Ctr};
use crypto::EncryptionInput::Plain;
use crypto::{
    create_full_id, ibe, seal_decrypt, seal_encrypt, Ciphertext, EncryptedObject, EncryptionInput,
    IBEEncryptions, IBEPublicKeys, IBEUserSecretKeys, ObjectID,
};
use fastcrypto::encoding::Encoding;
use fastcrypto::encoding::Hex;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar};
use rand::thread_rng;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// 密钥长度常量（字节）
const KEY_LENGTH: usize = 32;

/// 默认编码方式，用于序列化和反序列化值
type DefaultEncoding = Hex;

/**
 * CLI参数结构体
 * 
 * 使用clap库定义的命令行参数结构，包含所有可能的命令和选项
 */
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

/**
 * CLI支持的命令枚举
 * 
 * 定义了所有可用的子命令及其各自的参数
 */
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// 生成新的主密钥和公钥对
    /// 
    /// 此命令创建一个新的Boneh-Franklin IBE主密钥对，包括一个随机生成的
    /// 主密钥（私钥）和对应的公钥。主密钥应保密存储，公钥可以公开分发。
    Genkey,
    
    /// 从ID和主密钥提取用户私钥
    /// 
    /// 使用主密钥和用户ID提取对应的用户私钥。这个私钥允许用户解密
    /// 使用相应公钥和ID加密的消息。
    Extract {
        /// Sui网络上处理此密钥的KMS包的地址
        #[arg(long)]
        package_id: ObjectID,
        
        /// 应派生密钥的ID
        #[arg(long)]
        id: EncodedBytes,
        
        /// 主密钥。BLS12-381标量的Hex编码
        #[arg(long, value_parser = parse_serializable::<Scalar, DefaultEncoding>)]
        master_key: Scalar,
    },
    
    /// 验证用户私钥是否与公钥匹配
    /// 
    /// 检查给定的用户私钥是否对应于特定公钥和用户ID的有效私钥
    Verify {
        /// Sui网络上处理此密钥的KMS包的地址
        #[arg(long)]
        package_id: ObjectID,
        
        /// 应验证密钥的ID
        #[arg(long)]
        id: EncodedBytes,
        
        /// 用户私钥。压缩的BLS12-381 G1Element的Hex编码
        #[arg(long, value_parser = parse_serializable::<G1Element, DefaultEncoding>)]
        user_secret_key: G1Element,
        
        /// 公钥。压缩的BLS12-381 G2Element的Hex编码
        #[arg(long, value_parser = parse_serializable::<G2Element, DefaultEncoding>)]
        public_key: G2Element,
    },
    
    /// 使用Seal派生密钥（明文模式）
    /// 
    /// 使用基于身份的密钥封装机制(IBKEM)派生密钥，具体使用BLS12381上的Boneh-Franklin方案。
    /// 该命令输出可以公开共享的加密对象（以Hex编码的BCS序列化形式）和应私密保存的派生对称密钥。
    Plain {
        /// Sui网络上处理此密钥的KMS包的地址
        #[arg(long)]
        package_id: ObjectID,
        
        /// 应派生密钥的ID
        #[arg(long)]
        id: EncodedBytes,
        
        /// 解密所需的密钥服务器最小数量（阈值）
        #[arg(long)]
        threshold: u8,
        
        /// 密钥服务器的Hex编码公钥列表
        #[arg(value_parser = parse_serializable::<G2Element, DefaultEncoding>, num_args = 1..)]
        public_keys: Vec<G2Element>,
        
        /// 表示密钥服务器的Move对象地址列表
        #[arg(num_args = 1.., last = true)]
        object_ids: Vec<ObjectID>,
    },
    
    /// 使用Seal和AES-256-GCM加密消息
    /// 
    /// 使用基于身份的密钥封装机制(IBKEM)派生密钥，然后使用AES-256-GCM加密消息。
    /// 该命令输出可以公开共享的加密对象和应私密保存的派生对称密钥。
    EncryptAes {
        /// 要加密的消息（Hex编码字节）
        #[arg(long)]
        message: EncodedBytes,
        
        /// 可选的额外认证数据（Hex编码字节）
        #[arg(long)]
        aad: Option<EncodedBytes>,
        
        /// Sui网络上处理此加密的KMS包的地址
        #[arg(long)]
        package_id: ObjectID,
        
        /// 用于此加密的密钥ID
        #[arg(long)]
        id: EncodedBytes,
        
        /// 解密所需的密钥服务器最小数量（阈值）
        #[arg(long)]
        threshold: u8,
        
        /// 密钥服务器的Hex编码公钥列表
        #[arg(value_parser = parse_serializable::<G2Element, DefaultEncoding>, num_args = 1..)]
        public_keys: Vec<G2Element>,
        
        /// 表示密钥服务器的Move对象地址列表
        #[arg(num_args = 1.., last = true)]
        object_ids: Vec<ObjectID>,
    },
    
    /// 使用Seal和HMAC-256-CTR加密消息
    /// 
    /// 使用基于身份的密钥封装机制(IBKEM)派生密钥，然后使用计数器模式和hmac-sha3-256作为PRF加密消息。
    /// 该命令输出可以公开共享的加密对象和应私密保存的派生对称密钥。
    EncryptHmac {
        /// 要加密的消息（Hex编码字节）
        #[arg(long)]
        message: EncodedBytes,
        
        /// 可选的额外认证数据（Hex编码字节）
        #[arg(long)]
        aad: Option<EncodedBytes>,
        
        /// Sui网络上处理此加密的KMS包的地址
        #[arg(long)]
        package_id: ObjectID,
        
        /// 用于此加密的密钥ID
        #[arg(long)]
        id: EncodedBytes,
        
        /// 解密所需的密钥服务器最小数量（阈值）
        #[arg(long)]
        threshold: u8,
        
        /// 密钥服务器的Hex编码公钥列表
        #[arg(value_parser = parse_serializable::<G2Element, DefaultEncoding>, num_args = 1..)]
        public_keys: Vec<G2Element>,
        
        /// 表示密钥服务器的Move对象地址列表
        #[arg(num_args = 1.., last = true)]
        object_ids: Vec<ObjectID>,
    },
    
    /// 解密Seal加密对象
    /// 
    /// 使用提供的密钥服务器私钥解密加密对象。如果加密对象包含消息，则返回该消息。
    /// 如果使用了Plain模式，则返回派生的加密密钥。
    Decrypt {
        /// 加密对象（Hex编码字节）
        #[arg(value_parser = parse_serializable::<EncryptedObject, DefaultEncoding>)]
        encrypted_object: EncryptedObject,
        
        /// 密钥服务器的私钥列表。私钥顺序必须与object_ids字段中的密钥服务器顺序匹配
        #[arg(value_parser = parse_serializable::<G1Element, DefaultEncoding>, num_args = 1..)]
        secret_keys: Vec<G1Element>,
        
        /// 用于此解密的密钥服务器Move对象地址列表
        #[arg(num_args = 1.., last = true)]
        object_ids: Vec<ObjectID>,
    },
    
    /// 解析Seal加密对象
    /// 
    /// 解析并显示加密对象的各个组成部分，包括版本、包ID、加密份额等详细信息
    Parse {
        /// 加密对象（Hex编码字节）
        #[arg(value_parser = parse_serializable::<EncryptedObject, DefaultEncoding>)]
        encrypted_object: EncryptedObject,
    },
    
    /// 使用对称密钥直接解密加密对象
    /// 
    /// 当已知派生的对称密钥时，可以直接解密加密对象而无需使用私钥重建密钥
    SymmetricDecrypt {
        /// 加密对象（Hex编码字节）
        #[arg(value_parser = parse_serializable::<EncryptedObject, DefaultEncoding>)]
        encrypted_object: EncryptedObject,
        
        /// 加密时派生的对称密钥
        #[arg(long)]
        key: EncodedBytes,
    },
}

/// 生成密钥命令的输出结构
struct GenkeyOutput((Scalar, G2Element));

/// 提取用户私钥命令的输出结构
struct ExtractOutput(G1Element);

/// 验证命令的输出结构
struct VerifyOutput(FastCryptoResult<()>);

/// 加密命令的输出结构
struct EncryptionOutput((EncryptedObject, [u8; KEY_LENGTH]));

/// 解密命令的输出结构
struct DecryptionOutput(Vec<u8>);

/// 解析命令的输出结构
struct ParseOutput(EncryptedObject);

/// 对称解密命令的输出结构
struct SymmetricDecryptOutput(Vec<u8>);

/**
 * 主函数 - CLI入口点
 * 
 * 处理命令行参数并执行相应的命令，将结果格式化后输出
 */
fn main() -> FastCryptoResult<()> {
    // 解析命令行参数
    let args = Arguments::parse();

    // 根据命令执行相应的操作并格式化输出
    let output = match args.command {
        // 生成新的IBE密钥对
        Command::Genkey => GenkeyOutput(ibe::generate_key_pair(&mut thread_rng())).to_string(),
        
        // 从主密钥和ID提取用户私钥
        Command::Extract {
            package_id,
            id,
            master_key,
        } => ExtractOutput(ibe::extract(
            &master_key,
            &create_full_id(&package_id, &id.0),
        ))
        .to_string(),
        
        // 验证用户私钥是否与公钥匹配
        Command::Verify {
            package_id,
            id,
            user_secret_key,
            public_key,
        } => VerifyOutput(ibe::verify_user_secret_key(
            &user_secret_key,
            &create_full_id(&package_id, &id.0),
            &public_key,
        ))
        .to_string(),
        
        // 使用Seal派生密钥（明文模式）
        Command::Plain {
            package_id,
            id,
            threshold,
            public_keys,
            object_ids,
        } => EncryptionOutput(seal_encrypt(
            package_id,
            id.0,
            object_ids,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys),
            threshold,
            Plain,
        )?)
        .to_string(),
        
        // 使用Seal和AES-256-GCM加密消息
        Command::EncryptAes {
            message,
            aad,
            package_id,
            id,
            threshold,
            public_keys,
            object_ids,
        } => EncryptionOutput(seal_encrypt(
            package_id,
            id.0,
            object_ids,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys),
            threshold,
            EncryptionInput::Aes256Gcm {
                data: message.0,
                aad: aad.map(|a| a.0),
            },
        )?)
        .to_string(),
        
        // 使用Seal和HMAC-256-CTR加密消息
        Command::EncryptHmac {
            message,
            aad,
            package_id,
            id,
            threshold,
            public_keys,
            object_ids,
        } => EncryptionOutput(seal_encrypt(
            package_id,
            id.0,
            object_ids,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys),
            threshold,
            EncryptionInput::Hmac256Ctr {
                data: message.0,
                aad: aad.map(|a| a.0),
            },
        )?)
        .to_string(),
        
        // 解密Seal加密对象
        Command::Decrypt {
            encrypted_object,
            secret_keys,
            object_ids,
        } => DecryptionOutput(seal_decrypt(
            &encrypted_object,
            &IBEUserSecretKeys::BonehFranklinBLS12381(
                object_ids.into_iter().zip(secret_keys).collect(),
            ),
            None,
        )?)
        .to_string(),
        
        // 解析Seal加密对象
        Command::Parse { encrypted_object } => ParseOutput(encrypted_object).to_string(),
        
        // 使用对称密钥直接解密加密对象
        Command::SymmetricDecrypt {
            encrypted_object,
            key,
        } => {
            // 转换输入密钥为正确的格式
            let dem_key = key
                .0
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?;
            let EncryptedObject { ciphertext, .. } = encrypted_object;

            // 根据加密模式选择相应的解密方法
            match ciphertext {
                Ciphertext::Aes256Gcm { blob, aad } => {
                    Aes256Gcm::decrypt(&blob, &aad.unwrap_or(vec![]), &dem_key)
                }
                Ciphertext::Hmac256Ctr { blob, aad, mac } => {
                    Hmac256Ctr::decrypt(&blob, &mac, &aad.unwrap_or(vec![]), &dem_key)
                }
                _ => Err(FastCryptoError::InvalidInput),
            }
            .map(SymmetricDecryptOutput)?
            .to_string()
        }
    };
    
    // 输出结果
    println!("{}", output);
    Ok(())
}

/// 用于CLI二进制输入的类型
/// 
/// 包装了一个字节向量，用于处理Hex编码的输入参数
#[derive(Debug, Clone)]
struct EncodedBytes(Vec<u8>);

impl FromStr for EncodedBytes {
    type Err = FastCryptoError;

    /// 从字符串解析EncodedBytes
    /// 
    /// 将Hex编码的字符串解码为字节向量
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DefaultEncoding::decode(s).map(EncodedBytes)
    }
}

//
// 输出格式化
//

/**
 * 将可序列化对象转换为字符串
 * 
 * 使用BCS序列化对象，然后使用默认编码转换为字符串
 */
fn serializable_to_string<T: Serialize>(t: &T) -> String {
    DefaultEncoding::encode(bcs::to_bytes(t).expect("序列化失败"))
}

/**
 * 解析可序列化对象
 * 
 * 将编码的字符串解析为指定类型的对象
 */
pub fn parse_serializable<T: for<'a> Deserialize<'a>, E: Encoding>(s: &str) -> Result<T, String> {
    let bytes = E::decode(s).map_err(|e| format!("{}", e))?;
    bcs::from_bytes(&bytes).map_err(|e| format!("{}", e))
}

// 各命令输出的格式化实现

impl Display for GenkeyOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "主密钥: {}\n公钥: {}",
            serializable_to_string(&self.0 .0),
            serializable_to_string(&self.0 .1),
        )
    }
}

impl Display for ExtractOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "用户私钥: {}", serializable_to_string(&self.0))
    }
}

impl Display for VerifyOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            if self.0.is_ok() {
                "验证成功"
            } else {
                "验证失败"
            }
        )
    }
}

impl Display for EncryptionOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "加密对象 (BCS编码): {}\n对称密钥: {}",
            DefaultEncoding::encode(bcs::to_bytes(&self.0 .0).unwrap()),
            Hex::encode(self.0 .1)
        )
    }
}

impl Display for DecryptionOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "解密消息: {}", DefaultEncoding::encode(&self.0))
    }
}

impl Display for ParseOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "版本: {}", self.0.version)?;
        writeln!(f, "包ID: {}", self.0.package_id)?;
        writeln!(f, "ID: {}", DefaultEncoding::encode(&self.0.id))?;
        writeln!(f, "服务器列表及共享索引:")?;
        for (id, index) in &self.0.services {
            writeln!(f, "  {}: {}", id, index)?;
        }
        writeln!(f, "阈值: {}", self.0.threshold)?;
        writeln!(f, "密文:")?;
        match &self.0.ciphertext {
            Ciphertext::Aes256Gcm { blob, aad } => {
                writeln!(f, "  类型: AES-256-GCM")?;
                writeln!(f, "  数据: {}", DefaultEncoding::encode(blob))?;
                writeln!(
                    f,
                    "  额外认证数据: {}\n",
                    aad.as_ref()
                        .map_or("无".to_string(), DefaultEncoding::encode)
                )?;
            }
            Ciphertext::Hmac256Ctr { blob, aad, mac } => {
                writeln!(f, "  类型: HMAC-256-CTR")?;
                writeln!(f, "  数据: {}", DefaultEncoding::encode(blob))?;
                writeln!(
                    f,
                    "  额外认证数据: {}",
                    aad.as_ref()
                        .map_or("无".to_string(), DefaultEncoding::encode)
                )?;
                writeln!(f, "  MAC: {}", DefaultEncoding::encode(mac))?;
            }
            Ciphertext::Plain => {
                writeln!(f, "  类型: 明文")?;
            }
        }
        writeln!(f, "加密份额:")?;
        match &self.0.encrypted_shares {
            IBEEncryptions::BonehFranklinBLS12381 {
                encrypted_shares: shares,
                nonce: encapsulation,
                encrypted_randomness,
            } => {
                writeln!(f, "  类型: Boneh-Franklin BLS12-381")?;
                writeln!(f, "  份额列表:")?;
                for share in shares.iter() {
                    writeln!(f, "    {}", DefaultEncoding::encode(share))?;
                }
                writeln!(
                    f,
                    "  封装值: {}",
                    serializable_to_string(&encapsulation)
                )?;
                writeln!(
                    f,
                    "  加密随机性: {}",
                    DefaultEncoding::encode(encrypted_randomness)
                )?;
            }
        };
        Ok(())
    }
}

impl Display for SymmetricDecryptOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "解密消息: {}", DefaultEncoding::encode(&self.0))
    }
}
