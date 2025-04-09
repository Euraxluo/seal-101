// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of a the Boneh-Franklin Identity-based encryption scheme from https://eprint.iacr.org/2001/090 over the BLS12-381 curve construction.
//! It enables a symmetric key to be derived from the identity + the public key of a user and used to encrypt a fixed size message of length [KEY_LENGTH].

/**
 * 基于身份的加密 (IBE) 模块
 * 
 * 本模块实现了Boneh-Franklin基于身份的加密方案，该方案基于BLS12-381曲线构造。
 * 论文来源: https://eprint.iacr.org/2001/090
 * 
 * IBE允许使用用户的身份（如电子邮件地址）和系统公钥导出对称密钥，
 * 用于加密固定大小的消息（长度为KEY_SIZE）。这消除了传统公钥基础设施的复杂性。
 * 
 * 主要特点:
 * 1. 可以使用任意字符串（如用户ID）作为公钥
 * 2. 需要可信第三方（密钥生成中心）生成用户私钥
 * 3. 支持批量加密和确定性加密
 * 4. 提供密钥持有证明机制
 */

use crate::utils::xor;
use crate::{DST_POP, KEY_SIZE};
use fastcrypto::error::FastCryptoError::{GeneralError, InvalidInput};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::bls12381::{G1Element, G2Element, GTElement, Scalar};
use fastcrypto::groups::{GroupElement, HashToGroupElement, Pairing, Scalar as GenericScalar};
use fastcrypto::hmac::{hkdf_sha3_256, HkdfIkm};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::AllowedRng;
use fastcrypto::traits::ToFromBytes;
use sui_types::base_types::ObjectID;

/// 主密钥类型，用于生成系统参数和用户私钥
pub type MasterKey = Scalar;
/// 系统公钥类型，公开发布
pub type PublicKey = G2Element;
/// 用户私钥类型，由主密钥和用户身份派生
pub type UserSecretKey = G1Element;
/// 加密时使用的随机数类型，用于确保加密的安全性
pub type Nonce = G2Element;
/// 明文类型，固定大小
pub type Plaintext = [u8; KEY_SIZE];
/// 密文类型，与明文大小相同
pub type Ciphertext = [u8; KEY_SIZE];
/// 随机性类型，用于确定性加密
pub type Randomness = Scalar;

/// 密钥派生的附加信息类型
/// 包含密钥服务器的对象ID和分享索引
pub type Info = (ObjectID, u8);

/**
 * 生成IBE系统的密钥对
 * 
 * 创建由主密钥（私钥）和系统公钥组成的密钥对。
 * 主密钥应安全存储在密钥生成中心，公钥可以公开发布。
 * 
 * 参数:
 * @param rng - 随机数生成器
 * 
 * 返回:
 * 由主密钥和公钥组成的元组
 */
pub fn generate_key_pair<R: AllowedRng>(rng: &mut R) -> (MasterKey, PublicKey) {
    let sk = Scalar::rand(rng);
    (sk, public_key_from_master_key(&sk))
}

/**
 * 从主密钥派生公钥
 * 
 * 根据主密钥计算系统公钥。
 * 公钥计算为：PK = g^s，其中g是G2群的生成元，s是主密钥。
 * 
 * 参数:
 * @param master_key - 主密钥
 * 
 * 返回:
 * 派生的公钥
 */
pub fn public_key_from_master_key(master_key: &MasterKey) -> PublicKey {
    G2Element::generator() * master_key
}

/**
 * 提取用户私钥
 * 
 * 根据主密钥和用户身份ID提取用户私钥。
 * 用户私钥计算为：USK = H(ID)^s，其中H(ID)是将ID哈希到G1群的结果，s是主密钥。
 * 
 * 参数:
 * @param master_key - 系统的主密钥
 * @param id - 用户身份ID（如用户名、邮箱等）
 * 
 * 返回:
 * 用户的私钥
 */
pub fn extract(master_key: &MasterKey, id: &[u8]) -> UserSecretKey {
    G1Element::hash_to_group_element(id) * master_key
}

/**
 * 验证用户私钥的有效性
 * 
 * 检查给定的用户私钥是否对应于特定公钥和用户ID的有效私钥。
 * 验证通过检查配对等式：e(USK, g) = e(H(ID), PK)
 * 
 * 参数:
 * @param user_secret_key - 要验证的用户私钥
 * @param id - 用户身份ID
 * @param public_key - 系统公钥
 * 
 * 返回:
 * 如果私钥有效则返回Ok(())，否则返回错误
 */
pub fn verify_user_secret_key(
    user_secret_key: &UserSecretKey,
    id: &[u8],
    public_key: &PublicKey,
) -> FastCryptoResult<()> {
    if user_secret_key.pairing(&G2Element::generator())
        == G1Element::hash_to_group_element(id).pairing(public_key)
    {
        Ok(())
    } else {
        Err(InvalidInput)
    }
}

/**
 * 批量确定性加密
 * 
 * 使用相同的随机性和用户ID，为不同的公钥和明文批量加密消息。
 * 适用于多方加密场景，如阈值加密。
 * 
 * 参数:
 * @param randomness - 加密使用的随机性
 * @param plaintexts - 要加密的明文数组
 * @param public_keys - 接收者的公钥数组
 * @param id - 用户身份ID
 * @param infos - 用于密钥派生的附加信息
 * 
 * 返回:
 * 成功时返回(随机数, 密文数组)，失败时返回错误
 */
pub fn encrypt_batched_deterministic(
    randomness: &Randomness,
    plaintexts: &[Plaintext],
    public_keys: &[PublicKey],
    id: &[u8],
    infos: &[Info],
) -> FastCryptoResult<(Nonce, Vec<Ciphertext>)> {
    let batch_size = plaintexts.len();
    if batch_size != public_keys.len() || batch_size != infos.len() {
        return Err(InvalidInput);
    }

    let gid = G1Element::hash_to_group_element(id);
    let gid_r = gid * randomness;
    let nonce = G2Element::generator() * randomness;
    Ok((
        nonce,
        (0..batch_size)
            .map(|i| {
                xor(
                    &kdf(&gid_r.pairing(&public_keys[i]), &nonce, &gid, &infos[i]),
                    &plaintexts[i],
                )
            })
            .collect(),
    ))
}

/**
 * 使用用户私钥解密消息
 * 
 * 根据给定的随机数、密文和用户私钥解密消息。
 * 解密过程通过派生与加密时相同的对称密钥，并用XOR操作恢复明文。
 * 
 * 参数:
 * @param nonce - 加密时使用的随机数
 * @param ciphertext - 要解密的密文
 * @param secret_key - 用户的私钥
 * @param id - 用户身份ID
 * @param info - 用于密钥派生的附加信息
 * 
 * 返回:
 * 解密后的明文
 */
pub fn decrypt(
    nonce: &Nonce,
    ciphertext: &Ciphertext,
    secret_key: &UserSecretKey,
    id: &[u8],
    info: &Info,
) -> Plaintext {
    let gid = G1Element::hash_to_group_element(id);
    xor(
        ciphertext,
        &kdf(&secret_key.pairing(nonce), nonce, &gid, info),
    )
}

/**
 * 验证随机数是否由指定的随机性生成
 * 
 * 验证关系：nonce = g^randomness，其中g是G2群的生成元
 * 
 * 参数:
 * @param randomness - 生成随机数的随机性
 * @param nonce - 要验证的随机数
 * 
 * 返回:
 * 验证成功时返回Ok(())，失败时返回错误
 */
fn verify_nonce(randomness: &Randomness, nonce: &Nonce) -> FastCryptoResult<()> {
    if G2Element::generator() * randomness != *nonce {
        return Err(GeneralError("Invalid randomness".to_string()));
    }
    Ok(())
}

/**
 * 使用随机性进行确定性解密
 * 
 * 此方法允许知道随机性的一方解密，而不需要持有用户私钥。
 * 适用于多方加密方案和密钥恢复场景。
 * 
 * 参数:
 * @param randomness - 加密时使用的随机性
 * @param ciphertext - 要解密的密文
 * @param public_key - 接收者的公钥
 * @param id - 用户身份ID
 * @param info - 用于密钥派生的附加信息
 * 
 * 返回:
 * 成功时返回解密后的明文，失败时返回错误
 */
pub fn decrypt_deterministic(
    randomness: &Randomness,
    ciphertext: &Ciphertext,
    public_key: &PublicKey,
    id: &[u8],
    info: &Info,
) -> FastCryptoResult<Plaintext> {
    let gid = G1Element::hash_to_group_element(id);
    let gid_r = gid * randomness;
    let nonce = G2Element::generator() * randomness;
    Ok(xor(
        ciphertext,
        &kdf(&gid_r.pairing(public_key), &nonce, &gid, info),
    ))
}

/**
 * 密钥派生函数
 * 
 * 从公共输入派生对称密钥，用于加密和解密。
 * 密钥派生基于HKDF-SHA3-256算法。
 * 
 * 参数:
 * @param input - 配对计算结果(GT元素)
 * @param nonce - 加密时使用的随机数
 * @param gid - 哈希后的用户ID
 * @param (object_id, index) - 附加信息，包含对象ID和索引
 * 
 * 返回:
 * 派生的对称密钥
 */
fn kdf(
    input: &GTElement,
    nonce: &G2Element,
    gid: &G1Element,
    (object_id, index): &Info,
) -> [u8; KEY_SIZE] {
    let mut bytes = input.to_byte_array().to_vec(); // 576 bytes
    bytes.extend_from_slice(&nonce.to_byte_array()); // 96 bytes
    bytes.extend_from_slice(&gid.to_byte_array()); // 48 bytes

    let mut info = object_id.to_vec();
    info.extend_from_slice(&[*index]);

    hkdf_sha3_256(
        &HkdfIkm::from_bytes(&bytes).expect("not fixed length"),
        &[], // no salt
        &info,
        KEY_SIZE,
    )
    .expect("kdf should not fail")
    .try_into()
    .expect("same length")
}

/**
 * 使用密钥加密随机性
 * 
 * 通过对随机性和密钥进行XOR操作来加密随机性。
 * 
 * 参数:
 * @param randomness - 要加密的随机性
 * @param key - 用于加密的对称密钥
 * 
 * 返回:
 * 加密后的随机性
 */
pub fn encrypt_randomness(randomness: &Randomness, key: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    xor(key, &randomness.to_byte_array())
}

/**
 * 解密随机性并验证随机数
 * 
 * 使用派生密钥解密随机性，并验证该随机性是否生成了给定的随机数。
 * 
 * 参数:
 * @param encrypted_randomness - 加密的随机性
 * @param derived_key - 用于解密的派生密钥
 * @param nonce - 要验证的随机数
 * 
 * 返回:
 * 成功时返回解密的随机性，失败时返回错误
 */
pub fn decrypt_and_verify_nonce(
    encrypted_randomness: &[u8; KEY_SIZE],
    derived_key: &[u8; KEY_SIZE],
    nonce: &Nonce,
) -> FastCryptoResult<Randomness> {
    let randomness = Scalar::from_byte_array(&xor(derived_key, encrypted_randomness))?;
    verify_nonce(&randomness, nonce).map(|()| randomness)
}

/// 密钥持有证明类型，证明实体确实拥有特定的主密钥
pub type ProofOfPossession = G1Element;

/**
 * 创建主密钥持有证明
 * 
 * 生成一个证明，证明实体确实拥有与公钥对应的主密钥。
 * 该证明实际上是BLS签名，将公钥和消息绑定在一起。
 * 
 * 参数:
 * @param master_key - 主密钥
 * @param message - 要绑定的消息
 * 
 * 返回:
 * 密钥持有证明
 */
pub fn create_proof_of_possession(master_key: &MasterKey, message: &[u8]) -> ProofOfPossession {
    let public_key = public_key_from_master_key(master_key);
    let mut full_msg = DST_POP.to_vec();
    full_msg.extend(bcs::to_bytes(&public_key).expect("valid pk"));
    full_msg.extend(message);
    G1Element::hash_to_group_element(&full_msg) * master_key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试KDF函数的结果与TypeScript实现的一致性
    /// 确保Rust和TypeScript实现的KDF函数输出相同结果
    #[test]
    fn test_kdf_alignment_with_ts() {
        use fastcrypto::groups::GroupElement;

        // 使用固定的测试值
        let r = fastcrypto::groups::bls12381::Scalar::from(12345u128);
        let x = GTElement::generator() * r;
        let nonce = G2Element::generator() * r;
        let gid = G1Element::hash_to_group_element(&[0]);
        let object_id = ObjectID::new([0; 32]);

        // 计算派生密钥并与预期结果比较
        let derived_key = kdf(&x, &nonce, &gid, &(object_id, 42));
        let expected =
            hex::decode("1963b93f076d0dc97cbb38c3864b2d6baeb87c7eb99139100fd775b0b09f668b")
                .unwrap();
        assert_eq!(expected, derived_key);
    }
}
