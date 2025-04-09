// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! # Seal 密钥管理系统的密码学核心
//! 
//! 本模块实现了 Seal 密钥管理系统的核心密码学组件，提供了一套完整的加密、
//! 解密、密钥共享和密钥管理功能。系统采用身份基础加密(IBE)与阈值密钥共享(TSS)
//! 相结合的方式，实现了高安全性、可扩展的密钥管理解决方案。
//! 
//! ## 核心功能
//! 
//! * 加密数据并安全分发密钥共享 (`seal_encrypt`)
//! * 使用足够数量的密钥共享重建密钥并解密数据 (`seal_decrypt`)
//! * 基于身份的加密，无需复杂的PKI基础设施
//! * 阈值密钥共享，确保即使部分密钥服务器不可用也能完成解密
//! * 多种加密模式支持：AES-256-GCM、HMAC-256-CTR以及明文模式
//! 
//! ## 模块结构
//! 
//! * `dem`: 数据加密机制，提供对称加密算法
//! * `elgamal`: 基于椭圆曲线的ElGamal加密实现
//! * `gf256`: GF(256)有限域的数学运算
//! * `ibe`: 身份基础加密的实现
//! * `polynomial`: 多项式运算，用于秘密共享
//! * `tss`: 阈值秘密共享实现
//! * `utils`: 通用工具函数
//! 
//! ## 安全特性
//! 
//! * 阈值密钥共享确保即使部分密钥服务器被攻破，整体系统仍然安全
//! * 身份基础加密简化了密钥管理流程
//! * 认证加密保证数据完整性和真实性
//! * 密钥派生机制增强了系统安全性

use crate::dem::Hmac256Ctr;
use crate::ibe::{decrypt_deterministic, encrypt_batched_deterministic};
use crate::tss::{combine, interpolate, SecretSharing};
use dem::Aes256Gcm;
use fastcrypto::error::FastCryptoError::{GeneralError, InvalidInput};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::Scalar;
use fastcrypto::hmac::{hmac_sha3_256, HmacKey};
use itertools::Itertools;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
pub use sui_types::base_types::ObjectID;
use sui_types::crypto::ToFromBytes;
use tss::split;
use utils::generate_random_bytes;

// 子模块声明
pub mod dem;         // 数据加密机制模块
pub mod elgamal;     // ElGamal加密模块
pub mod gf256;       // GF(256)有限域数学模块
pub mod ibe;         // 身份基础加密模块
mod polynomial;      // 多项式计算模块
pub mod tss;         // 阈值秘密共享模块
mod utils;           // 工具函数模块

/// 用于哈希到椭圆曲线群的域分隔标签
pub const DST: &[u8] = b"SUI-SEAL-IBE-BLS12381-00";

/// 用于密钥持有证明的哈希到椭圆曲线群的域分隔标签
pub const DST_POP: &[u8] = b"SUI-SEAL-IBE-BLS12381-POP-00";

/// 密钥大小（字节数）
pub const KEY_SIZE: usize = 32;

/// 表示一个加密对象，包含加密数据及其密钥共享信息
/// 与TypeScript类型保持一致
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedObject {
    /// 版本号，用于兼容性检查
    pub version: u8,
    /// 包ID，用于身份标识
    pub package_id: ObjectID,
    /// 内部ID，与package_id一起构成完整身份
    pub id: Vec<u8>,
    /// 密钥服务器地址及其共享索引列表
    pub services: Vec<(ObjectID, u8)>,
    /// 解密所需的最小共享数量（阈值）
    pub threshold: u8,
    /// 加密的密钥共享
    pub encrypted_shares: IBEEncryptions,
    /// 实际的密文数据
    pub ciphertext: Ciphertext,
}

/// 加密数据的密文类型
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Ciphertext {
    /// 使用AES-256-GCM进行加密的数据
    Aes256Gcm {
        /// 加密后的数据
        blob: Vec<u8>,
        /// 额外的认证数据（可选）
        aad: Option<Vec<u8>>,
    },
    /// 使用HMAC-256-CTR进行加密的数据
    Hmac256Ctr {
        /// 加密后的数据
        blob: Vec<u8>,
        /// 额外的认证数据（可选）
        aad: Option<Vec<u8>>,
        /// 认证标签
        mac: [u8; KEY_SIZE],
    },
    /// 明文模式（不进行加密，只派生密钥）
    Plain,
}

/// IBE加密数据类型
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IBEEncryptions {
    /// 基于BLS12-381曲线的Boneh-Franklin IBE加密
    BonehFranklinBLS12381 {
        /// 加密使用的随机数
        nonce: ibe::Nonce,
        /// 加密后的密钥共享列表
        encrypted_shares: Vec<[u8; KEY_SIZE]>,
        /// 加密的随机性，用于验证
        encrypted_randomness: [u8; KEY_SIZE],
    },
}

/// IBE公钥类型
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IBEPublicKeys {
    /// 基于BLS12-381曲线的Boneh-Franklin IBE公钥列表
    BonehFranklinBLS12381(Vec<ibe::PublicKey>),
}

/// IBE用户私钥类型，用于解密
pub enum IBEUserSecretKeys {
    /// 基于BLS12-381曲线的Boneh-Franklin IBE用户私钥集合
    BonehFranklinBLS12381(HashMap<ObjectID, ibe::UserSecretKey>),
}

/// 加密输入数据类型
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EncryptionInput {
    /// 使用AES-256-GCM进行加密的输入
    Aes256Gcm { data: Vec<u8>, aad: Option<Vec<u8>> },
    /// 使用HMAC-256-CTR进行加密的输入
    Hmac256Ctr { data: Vec<u8>, aad: Option<Vec<u8>> },
    /// 明文模式（不进行加密，只派生密钥）
    Plain,
}

/// 加密指定的明文数据。加密过程如下：
/// 1. 生成随机AES密钥并使用该密钥加密消息
/// 2. 使用阈值秘密共享(TSS)将密钥分成多个共享，每个密钥服务器一个
/// 3. 使用身份基础加密(IBE)对每个共享进行加密
/// 4. 返回密文、加密的共享和用于加密的随机数
///
/// @param package_id 包ID，用于构建完整身份
/// @param id 内部ID，与package_id一起构成完整身份
/// @param key_servers 用于加密的密钥服务器列表
/// @param public_keys 密钥服务器的公钥
/// @param threshold TSS的阈值，至少需要这么多共享才能重建密钥
/// @param encryption_input 加密输入数据
/// @return 加密对象和用于加密的派生对称密钥
pub fn seal_encrypt(
    package_id: ObjectID,
    id: Vec<u8>,
    key_servers: Vec<ObjectID>,
    public_keys: &IBEPublicKeys,
    threshold: u8,
    encryption_input: EncryptionInput,
) -> FastCryptoResult<(EncryptedObject, [u8; KEY_SIZE])> {
    // 验证阈值参数
    let number_of_shares = key_servers.len() as u8;
    if threshold > number_of_shares || threshold == 0 {
        return Err(InvalidInput);
    }

    // 创建随机数生成器
    let mut rng = thread_rng();
    // 创建完整ID，用于IBE加密
    let full_id = create_full_id(&package_id, &id);

    // 生成随机基础密钥
    let base_key = generate_random_bytes(&mut rng);

    // 派生用于对称加密的密钥
    let dem_key = derive_key(KeyPurpose::DEM, &base_key);
    // 根据加密模式加密数据
    let ciphertext = match encryption_input {
        EncryptionInput::Aes256Gcm { data, aad } => Ciphertext::Aes256Gcm {
            blob: Aes256Gcm::encrypt(&data, aad.as_ref().unwrap_or(&vec![]), &dem_key),
            aad,
        },
        EncryptionInput::Hmac256Ctr { data, aad } => {
            let (blob, mac) = Hmac256Ctr::encrypt(&data, aad.as_ref().unwrap_or(&vec![]), &dem_key);
            Ciphertext::Hmac256Ctr { blob, mac, aad }
        }
        EncryptionInput::Plain => Ciphertext::Plain,
    };

    // 使用阈值秘密共享对基础密钥进行分享
    let SecretSharing {
        indices, shares, ..
    } = split(&mut rng, base_key, threshold, number_of_shares)?;

    // 将密钥服务器ID与共享索引配对
    let services = key_servers.into_iter().zip(indices).collect::<Vec<_>>();

    // 根据公钥类型选择IBE加密方法
    let encrypted_shares = match public_keys {
        IBEPublicKeys::BonehFranklinBLS12381(public_keys) => {
            // 验证公钥数量是否正确
            if public_keys.len() != number_of_shares as usize {
                return Err(InvalidInput);
            }
            // 生成随机值用于IBE加密
            let randomness = ibe::Randomness::rand(&mut rng);

            // 使用IBE加密共享
            // 使用共享索引作为IBE解密的索引参数，允许为同一身份的多个共享使用相同的公钥加密
            let (nonce, encrypted_shares) = encrypt_batched_deterministic(
                &randomness,
                &shares,
                public_keys,
                &full_id,
                &services,
            )?;

            // 加密随机值，用于验证
            let encrypted_randomness = ibe::encrypt_randomness(
                &randomness,
                &derive_key(KeyPurpose::EncryptedRandomness, &base_key),
            );
            IBEEncryptions::BonehFranklinBLS12381 {
                nonce,
                encrypted_shares,
                encrypted_randomness,
            }
        }
    };

    // 返回加密对象和派生的对称密钥
    Ok((
        EncryptedObject {
            version: 0,
            package_id,
            id,
            services,
            threshold,
            encrypted_shares,
            ciphertext,
        },
        dem_key,
    ))
}

/// 解密给定的密文。解密过程如下：
/// 1. 使用用户私钥为给定的随机数解封IBE密钥
/// 2. 使用IBE密钥解密共享
/// 3. 使用足够数量的共享重建AES密钥
/// 4. 使用AES密钥解密密文
///
/// @param encrypted_object 加密对象，由`seal_encrypt`生成
/// @param user_secret_keys 用户私钥。假设这些密钥已经过验证，否则解密将失败，或者在使用`Plain`模式的情况下，派生的密钥将不正确
/// @param public_keys 密钥服务器的公钥。如果提供，所有共享将被解密并检查一致性
/// @return 解密后的明文数据，或者如果使用了`Plain`模式，则返回派生的密钥
pub fn seal_decrypt(
    encrypted_object: &EncryptedObject,
    user_secret_keys: &IBEUserSecretKeys,
    public_keys: Option<&IBEPublicKeys>,
) -> FastCryptoResult<Vec<u8>> {
    let EncryptedObject {
        version,
        package_id,
        id,
        encrypted_shares,
        services,
        threshold,
        ciphertext,
        ..
    } = encrypted_object;

    // 检查版本兼容性
    if *version != 0 {
        return Err(InvalidInput);
    }

    // 创建完整ID，用于IBE解密
    let full_id = create_full_id(package_id, id);

    // 根据IBE类型解密共享
    let shares = match (&encrypted_shares, user_secret_keys) {
        (
            IBEEncryptions::BonehFranklinBLS12381 {
                nonce,
                encrypted_shares,
                ..
            },
            IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
        ) => {
            // 检查加密对象是否有效
            // 例如，每个服务是否都有一个对应的加密共享
            if encrypted_shares.len() != services.len() {
                return Err(InvalidInput);
            }

            // 找出我们拥有私钥的服务索引
            let service_indices: Vec<usize> = services
                .iter()
                .enumerate()
                .filter(|(_, (id, _))| user_secret_keys.contains_key(id))
                .map(|(i, _)| i)
                .collect();
            // 检查我们是否有足够的私钥来达到阈值
            if service_indices.len() < *threshold as usize {
                return Err(InvalidInput);
            }

            // 使用私钥解密每个共享
            service_indices
                .into_iter()
                .map(|i| {
                    let index = services[i].1;
                    (index, ibe::decrypt(
                        nonce,
                        &encrypted_shares[i],
                        user_secret_keys
                            .get(&services[i].0)
                            .expect("这不应该发生：上面已经检查过这个私钥是否可用"),
                        &full_id,
                        &services[i],
                    ))
                })
                .collect_vec()
        }
    };

    // 使用共享重建基础密钥
    let base_key = combine(&shares)?;

    // 如果提供了公钥，可以解密所有共享并检查一致性
    if let Some(public_keys) = public_keys {
        encrypted_shares.check_share_consistency(
            &shares,
            &full_id,
            services,
            public_keys,
            &base_key,
        )?;
    }

    // 派生对称密钥并解密密文
    let dem_key = derive_key(KeyPurpose::DEM, &base_key);
    match ciphertext {
        Ciphertext::Aes256Gcm { blob, aad } => {
            Aes256Gcm::decrypt(blob, aad.as_ref().map_or(&[], |v| v), &dem_key)
        }
        Ciphertext::Hmac256Ctr { blob, aad, mac } => {
            Hmac256Ctr::decrypt(blob, mac, aad.as_ref().map_or(&[], |v| v), &dem_key)
        }
        Ciphertext::Plain => Ok(dem_key.to_vec()),
    }
}

/// 从DST、包ID和内部ID创建完整ID。结果的格式为：
/// [len(DST)][DST][package_id][id]
pub fn create_full_id(package_id: &[u8; 32], id: &[u8]) -> Vec<u8> {
    assert!(DST.len() < 256);
    let mut full_id = vec![DST.len() as u8];
    full_id.extend_from_slice(DST);
    full_id.extend_from_slice(package_id);
    full_id.extend_from_slice(id);
    full_id
}

/// 表示派生密钥的不同用途
pub enum KeyPurpose {
    /// 用于加密随机性的密钥
    EncryptedRandomness,
    /// 用于数据加密机制(DEM)的密钥
    DEM,
}

/// 从基础密钥为特定用途派生一个密钥
fn derive_key(purpose: KeyPurpose, derived_key: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    let hmac_key = HmacKey::from_bytes(derived_key).expect("固定长度");
    match purpose {
        KeyPurpose::EncryptedRandomness => hmac_sha3_256(&hmac_key, &[0]).digest,
        KeyPurpose::DEM => hmac_sha3_256(&hmac_key, &[1]).digest,
    }
}

impl IBEEncryptions {
    /// 给定共享和基础密钥，检查共享是否一致
    /// 例如，检查所有子集的共享是否能重建相同的多项式
    fn check_share_consistency(
        &self,
        shares: &[(u8, [u8; KEY_SIZE])],
        full_id: &[u8],
        services: &[(ObjectID, u8)],
        public_keys: &IBEPublicKeys,
        base_key: &[u8; KEY_SIZE],
    ) -> FastCryptoResult<()> {
        // 从给定的共享计算整个多项式，注意多项式(0) = base_key
        let polynomial = interpolate(shares)?;

        // 使用派生的密钥解密所有共享
        let all_shares = self.decrypt_all_shares(full_id, services, public_keys, base_key)?;

        // 检查所有共享是否都在重建的多项式上
        if all_shares
            .into_iter()
            .any(|(i, share)| polynomial(i) != share)
        {
            return Err(GeneralError("共享不一致".to_string()));
        }
        Ok(())
    }

    /// 给定派生的密钥，解密所有共享
    fn decrypt_all_shares(
        &self,
        full_id: &[u8],
        services: &[(ObjectID, u8)],
        public_keys: &IBEPublicKeys,
        base_key: &[u8; KEY_SIZE],
    ) -> FastCryptoResult<Vec<(u8, [u8; KEY_SIZE])>> {
        match self {
            IBEEncryptions::BonehFranklinBLS12381 {
                encrypted_randomness,
                encrypted_shares,
                nonce,
            } => {
                // 解密加密的随机数
                let nonce = ibe::decrypt_and_verify_nonce(
                    encrypted_randomness,
                    &derive_key(KeyPurpose::EncryptedRandomness, base_key),
                    nonce,
                )?;

                // 解密所有共享
                match public_keys {
                    IBEPublicKeys::BonehFranklinBLS12381(public_keys) => {
                        if public_keys.len() != encrypted_shares.len() {
                            return Err(InvalidInput);
                        }
                        public_keys
                            .iter()
                            .zip(encrypted_shares)
                            .zip(services)
                            .map(|((pk, s), service)| {
                                decrypt_deterministic(&nonce, s, pk, full_id, service)
                                    .map(|s| (service.1, s))
                            })
                            .collect::<FastCryptoResult<_>>()
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::{
        encoding::{Base64, Encoding},
        groups::{
            bls12381::{G1Element, Scalar},
            HashToGroupElement,
        },
        serde_helpers::ToFromByteArray,
    };
    use std::str::FromStr;

    /// 测试哈希函数的回归测试
    /// 确保哈希结果与预期值一致，避免意外的行为变化
    #[test]
    fn test_hash_with_prefix_regression() {
        let hash = G1Element::hash_to_group_element(&create_full_id(
            &ObjectID::from_bytes([0u8; 32]).unwrap(),
            &[1, 2, 3, 4],
        ));
        assert_eq!(hex::encode(hash.to_byte_array()), "b32685b6ffd1f373faf3abb10c05772e033f75da8af729c3611d81aea845670db48ceadd0132d3a667dbbaa36acefac7");
    }

    /// 测试使用AES-256-GCM模式的加密和解密完整流程
    /// 1. 创建密钥对和测试数据
    /// 2. 加密数据
    /// 3. 解密数据并验证结果
    /// 4. 验证AAD更改时解密失败
    #[test]
    fn test_encryption_round_trip_aes() {
        let data = b"Hello, World!";
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];

        let full_id = create_full_id(&package_id, &id);

        // 生成3对密钥，阈值设为2
        let mut rng = rand::thread_rng();
        let keypairs = (0..3)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .collect_vec();

        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();

        let threshold = 2;
        let public_keys =
            IBEPublicKeys::BonehFranklinBLS12381(keypairs.iter().map(|(_, pk)| *pk).collect_vec());

        // 加密数据
        let encrypted = seal_encrypt(
            package_id,
            id,
            services.clone(),
            &public_keys,
            threshold,
            EncryptionInput::Aes256Gcm {
                data: data.to_vec(),
                aad: Some(b"something".to_vec()),
            },
        )
        .unwrap()
        .0;

        // 准备用户私钥并解密
        let user_secret_keys = IBEUserSecretKeys::BonehFranklinBLS12381(
            services
                .into_iter()
                .zip(keypairs)
                .map(|(s, kp)| (s, ibe::extract(&kp.0, &full_id)))
                .collect(),
        );
        let decrypted = seal_decrypt(&encrypted, &user_secret_keys, Some(&public_keys)).unwrap();

        // 验证解密结果
        assert_eq!(data, decrypted.as_slice());

        // 验证AAD更改时解密失败
        let mut modified_encrypted = encrypted.clone();
        match modified_encrypted.ciphertext {
            Ciphertext::Aes256Gcm { ref mut aad, .. } => {
                match aad {
                    None => panic!(),
                    Some(ref mut aad) => aad.push(0),
                }
                assert!(
                    seal_decrypt(&modified_encrypted, &user_secret_keys, Some(&public_keys))
                        .is_err()
                );
            }
            _ => panic!(),
        }
    }

    /// 测试使用HMAC-256-CTR模式的加密和解密完整流程
    /// 1. 创建密钥对和测试数据
    /// 2. 加密数据
    /// 3. 解密数据并验证结果
    /// 4. 验证AAD更改时解密失败
    #[test]
    fn test_encryption_round_trip_hmac() {
        let data = b"Hello, World!";
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];

        let full_id = create_full_id(&package_id, &id);

        // 生成3对密钥，阈值设为2
        let mut rng = rand::thread_rng();
        let keypairs = (0..3)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .collect_vec();

        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();

        let threshold = 2;
        let public_keys =
            IBEPublicKeys::BonehFranklinBLS12381(keypairs.iter().map(|(_, pk)| *pk).collect_vec());

        // 加密数据
        let encrypted = seal_encrypt(
            package_id,
            id,
            services.clone(),
            &public_keys,
            threshold,
            EncryptionInput::Hmac256Ctr {
                data: data.to_vec(),
                aad: Some(b"something".to_vec()),
            },
        )
        .unwrap()
        .0;

        // 准备用户私钥并解密
        let user_secret_keys = IBEUserSecretKeys::BonehFranklinBLS12381(
            services
                .into_iter()
                .zip(keypairs)
                .map(|(s, kp)| (s, ibe::extract(&kp.0, &full_id)))
                .collect(),
        );
        let decrypted = seal_decrypt(&encrypted, &user_secret_keys, Some(&public_keys)).unwrap();

        // 验证解密结果
        assert_eq!(data, decrypted.as_slice());

        // 验证AAD更改时解密失败
        let mut modified_encrypted = encrypted.clone();
        match modified_encrypted.ciphertext {
            Ciphertext::Hmac256Ctr { ref mut aad, .. } => {
                match aad {
                    None => panic!(),
                    Some(ref mut aad) => aad.push(0),
                }
                assert!(
                    seal_decrypt(&modified_encrypted, &user_secret_keys, Some(&public_keys))
                        .is_err()
                );
            }
            _ => panic!(),
        }
    }

    /// 测试明文模式（Plain）的加密和解密流程
    /// 此模式不加密实际数据，只返回派生的对称密钥
    #[test]
    fn test_plain_round_trip() {
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];
        let full_id = create_full_id(&package_id, &id);

        // 生成3对密钥，阈值设为2
        let mut rng = rand::thread_rng();
        let keypairs = (0..3)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .collect_vec();

        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();

        let threshold = 2;
        let public_keys =
            IBEPublicKeys::BonehFranklinBLS12381(keypairs.iter().map(|(_, pk)| *pk).collect_vec());

        // 加密（明文模式）
        let (encrypted, key) = seal_encrypt(
            package_id,
            id,
            services.clone(),
            &public_keys,
            threshold,
            EncryptionInput::Plain,
        )
        .unwrap();

        // 准备用户私钥
        let user_secret_keys = services
            .into_iter()
            .zip(keypairs)
            .map(|(s, kp)| (s, ibe::extract(&kp.0, &full_id)))
            .collect();

        // 验证解密结果就是原始密钥
        assert_eq!(
            key.to_vec(),
            seal_decrypt(
                &encrypted,
                &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
                Some(&public_keys),
            )
            .unwrap()
        );
    }

    /// 测试与TypeScript实现的兼容性
    /// 使用预定义的测试向量确保跨语言实现的一致性
    #[test]
    fn typescript_test_vector() {
        // 使用固定的测试数据
        let package_id = [0u8; 32];
        let inner_id = [1, 2, 3, 4];

        // 从Base64字符串解析主密钥
        let master_keys = [
            "KPUXJQxoijA276hI6XhNVgIewyaija8UABeFTwEeD6k=",
            "AwuqCSqP/vHF+/roqrhjzKj070ouLFGWkYr9msDv9eQ=",
            "JyScQKCG091JJvmedlGFO+lBmsZKynKe3h8jbUlCA7o=",
        ]
        .iter()
        .map(|key| {
            Scalar::from_byte_array(&Base64::decode(key).unwrap().try_into().unwrap()).unwrap()
        })
        .collect::<Vec<_>>();
        
        // 从主密钥派生公钥
        let public_keys = master_keys
            .iter()
            .map(ibe::public_key_from_master_key)
            .collect_vec();

        // 从Base64字符串解析预先加密的数据
        let encryption = Base64::decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAECAwQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM3AgCEgtXcUe2iGMS8zEMEB9YVJo4WbdUuW7uqNBLEJc+xA0pnC6TNep2SGpudVO3gXtAG7W4lSNmc/xMhFv9WDfaTZfppIk7H6IXEmM8aUfjk6TyXtMO2D5T0PzB3HhTNIo4De81Z5tb7mnshJWTjJtHBoeWWUpoSunAGQQAWsGFQ5NK9AnAugziSj/SnS5I042nRGswaeMmTBG5+FyLP1FJPSadWZGTQSZzQGcRVVefDJw5gUxUVMhT+CfesAVHHZKkanKv0UhCEy3EnKc6Bkrl09fSLqo7hTKwqNxCJf9oaHhkAJ81y6phEffQ8F4xsbi87mpR05qGNtzvbyh/Y4PLhhL8yQyy4gxhPHwEEAQIDBA==").unwrap();
        let encryption: EncryptedObject = bcs::from_bytes(&encryption).unwrap();

        // 创建固定的对象ID
        let object_ids = [
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000000000000000000000000000003",
        ]
        .iter()
        .map(|id| ObjectID::from_str(id).unwrap())
        .collect::<Vec<_>>();

        // 创建完整ID和用户私钥
        let full_id = create_full_id(&package_id, &inner_id);
        let user_secret_keys = object_ids
            .into_iter()
            .zip(master_keys)
            .map(|(s, k)| (s, ibe::extract(&k, &full_id)))
            .collect();

        // 解密并验证结果
        let decrypted = seal_decrypt(
            &encryption,
            &IBEUserSecretKeys::BonehFranklinBLS12381(user_secret_keys),
            Some(&IBEPublicKeys::BonehFranklinBLS12381(public_keys)),
        )
        .unwrap();

        assert_eq!(decrypted, b"My super secret message");
    }

    /// 测试共享一致性检查
    /// 验证共享修改时的系统行为：
    /// 1. 如果不验证一致性，使用t个有效共享可以成功解密
    /// 2. 如果验证一致性，会检测到共享不一致并失败
    #[test]
    fn test_share_consistency() {
        let data = b"Hello, World!";
        let package_id = ObjectID::random();
        let id = vec![1, 2, 3, 4];

        let full_id = create_full_id(&package_id, &id);

        // 生成3对密钥，阈值设为2
        let mut rng = rand::thread_rng();
        let keypairs = (0..3)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .collect_vec();

        let services = keypairs.iter().map(|_| ObjectID::random()).collect_vec();

        let threshold = 2;
        let public_keys =
            IBEPublicKeys::BonehFranklinBLS12381(keypairs.iter().map(|(_, pk)| *pk).collect_vec());

        // 加密数据
        let mut encrypted = seal_encrypt(
            package_id,
            id.clone(),
            services.clone(),
            &public_keys,
            threshold,
            EncryptionInput::Hmac256Ctr {
                data: data.to_vec(),
                aad: Some(b"something".to_vec()),
            },
        )
        .unwrap()
        .0;

        // 准备用户私钥
        let usks: [_; 3] = services
            .iter()
            .zip(&keypairs)
            .map(|(s, kp)| (*s, ibe::extract(&kp.0, &full_id)))
            .collect_vec()
            .try_into()
            .unwrap();

        // 故意修改最后一个共享
        let encrypted_valid_shares = match encrypted.encrypted_shares.clone() {
            IBEEncryptions::BonehFranklinBLS12381 {
                nonce,
                mut encrypted_shares,
                encrypted_randomness,
            } => {
                encrypted_shares[2][0] = encrypted_shares[2][0].wrapping_add(1);
                IBEEncryptions::BonehFranklinBLS12381 {
                    nonce,
                    encrypted_shares,
                    encrypted_randomness,
                }
            }
        };
        encrypted.encrypted_shares = encrypted_valid_shares;

        // 使用所有共享解密应该失败（MAC错误）
        assert!(seal_decrypt(
            &encrypted,
            &IBEUserSecretKeys::BonehFranklinBLS12381(HashMap::from(usks)),
            None,
        )
        .is_err_and(|e| e == GeneralError("Invalid MAC".to_string())));

        // 只使用前两个有效共享
        let usks = IBEUserSecretKeys::BonehFranklinBLS12381(HashMap::from([usks[0], usks[1]]));

        // 不检查共享一致性时，可以成功解密
        assert_eq!(seal_decrypt(&encrypted, &usks, None,).unwrap(), data);

        // 检查共享一致性时，应该失败
        assert!(seal_decrypt(&encrypted, &usks, Some(&public_keys),)
            .is_err_and(|e| e == GeneralError("共享不一致".to_string())));
    }
}
