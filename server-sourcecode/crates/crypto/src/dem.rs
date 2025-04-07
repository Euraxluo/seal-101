// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 数据加密机制(DEM)模块
 * 
 * DEM(Data Encapsulation Mechanism)是混合加密系统中用于加密实际数据的部分。
 * 本模块提供两种对称加密算法的实现:
 * 1. Aes256Gcm - 基于AES-GCM的认证加密
 * 2. Hmac256Ctr - 基于HMAC-SHA3-256和CTR模式的自定义认证加密
 * 
 * 这些加密机制通常与密钥封装机制(KEM)一起使用，构成完整的混合加密系统。
 * KEM负责安全地传递对称密钥，而DEM使用该密钥加密实际消息。
 * 
 * 两种实现都支持关联数据(AAD)的认证加密，确保密文和关联数据的完整性和真实性。
 */

use crate::utils::xor_unchecked;
use crate::KEY_SIZE;
use fastcrypto::error::FastCryptoError;
use fastcrypto::hmac::HmacKey;
use fastcrypto::{
    aes::{
        Aes256Gcm as ExternalAes256Gcm, AesKey, AuthenticatedCipher, GenericByteArray,
        InitializationVector,
    },
    error::FastCryptoResult,
    traits::ToFromBytes,
};
use typenum::U16;

/// AES-256-GCM认证加密实现
/// 提供基于AES-GCM的加密和解密功能，包括关联数据的认证
pub struct Aes256Gcm;

impl Aes256Gcm {
    /**
     * 使用AES-256-GCM加密消息
     *
     * 使用固定的初始向量(IV)和提供的密钥加密消息，同时认证关联数据(AAD)。
     * 由于使用固定IV，每个密钥应该只使用一次。
     *
     * 参数:
     * @param msg - 要加密的明文
     * @param aad - 需要认证但不需要加密的关联数据
     * @param key - 32字节加密密钥
     *
     * 返回:
     * 包含认证标签的密文
     */
    pub fn encrypt(msg: &[u8], aad: &[u8], key: &[u8; KEY_SIZE]) -> Vec<u8> {
        ExternalAes256Gcm::new(AesKey::from_bytes(key).expect("Never fails for 32 byte input"))
            .encrypt_authenticated(&Self::iv(), aad, msg)
    }

    /**
     * 使用AES-256-GCM解密密文
     *
     * 使用固定的初始向量(IV)和提供的密钥解密密文，同时验证关联数据(AAD)的完整性。
     * 如果认证失败，将返回错误。
     *
     * 参数:
     * @param ciphertext - 包含认证标签的密文
     * @param aad - 需要认证的关联数据，必须与加密时使用的相同
     * @param key - 32字节解密密钥
     *
     * 返回:
     * 成功时返回解密的明文，失败时返回错误
     */
    pub fn decrypt(
        ciphertext: &[u8],
        aad: &[u8],
        key: &[u8; KEY_SIZE],
    ) -> FastCryptoResult<Vec<u8>> {
        ExternalAes256Gcm::new(AesKey::from_bytes(key).expect("Never fails for 32 byte input"))
            .decrypt_authenticated(&Self::iv(), aad, ciphertext)
    }
}

impl Aes256Gcm {
    /// 使用固定的初始向量(IV)。由于密钥从不重用，这是安全的。
    const IV: [u8; 16] = [
        138, 55, 153, 253, 198, 46, 121, 219, 160, 128, 89, 7, 214, 156, 148, 220,
    ];

    /// 获取固定的初始向量(IV)
    fn iv() -> InitializationVector<U16> {
        GenericByteArray::from_bytes(&Self::IV).expect("fixed value")
    }
}

/**
 * 使用CTR模式和HMAC-SHA3-256作为PRF的认证加密
 * 
 * 加密过程:
 * 1. 派生加密密钥 k₁ = hmac(key, 1)
 * 2. 将消息分块为32字节的块 m = m₁ || ... || mₙ
 * 3. 密文定义为 c = c₁ || ... || cₙ，其中 cᵢ = mᵢ ⊕ hmac(k₁, i)
 * 4. 计算AAD和密文的MAC: mac = hmac(k₂, aad || c)，其中 k₂ = hmac(key, 2)
 * 5. 返回 mac || c
 */
pub struct Hmac256Ctr;

impl Hmac256Ctr {
    /**
     * 使用HMAC-CTR模式加密消息
     *
     * 使用CTR模式加密消息，并计算关联数据和密文的MAC值。
     *
     * 参数:
     * @param msg - 要加密的明文
     * @param aad - 需要认证但不需要加密的关联数据
     * @param key - 32字节加密密钥
     *
     * 返回:
     * 密文和MAC值的元组
     */
    pub fn encrypt(msg: &[u8], aad: &[u8], key: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let ciphertext = encrypt_in_ctr_mode(key, msg);
        let mac = compute_mac(key, aad, &ciphertext);
        (ciphertext, mac)
    }

    /**
     * 使用HMAC-CTR模式解密密文
     *
     * 首先验证MAC值是否正确，然后使用CTR模式解密密文。
     * 如果MAC验证失败，将返回错误。
     *
     * 参数:
     * @param ciphertext - 要解密的密文
     * @param mac - 密文的MAC值
     * @param aad - 需要认证的关联数据，必须与加密时使用的相同
     * @param key - 32字节解密密钥
     *
     * 返回:
     * 成功时返回解密的明文，失败时返回错误
     */
    pub fn decrypt(
        ciphertext: &[u8],
        mac: &[u8; 32],
        aad: &[u8],
        key: &[u8; 32],
    ) -> FastCryptoResult<Vec<u8>> {
        let actual_mac = compute_mac(key, aad, ciphertext);
        if mac != &actual_mac {
            return Err(FastCryptoError::GeneralError("Invalid MAC".to_string()));
        }
        let msg = encrypt_in_ctr_mode(key, ciphertext);
        Ok(msg)
    }
}

/**
 * 使用HMAC-SHA3-256作为PRF在CTR模式下加密消息
 *
 * CTR模式加密是通过将每个明文块与密钥流块进行XOR操作实现的，
 * 其中密钥流是由HMAC-SHA3-256函数生成的。
 *
 * 参数:
 * @param key - 32字节主密钥
 * @param msg - 要加密的明文
 *
 * 返回:
 * 加密后的密文
 *
 * 注意: 对于CTR模式，加密和解密操作相同。
 */
fn encrypt_in_ctr_mode(key: &[u8; KEY_SIZE], msg: &[u8]) -> Vec<u8> {
    // Derive encryption key
    let encryption_key = hmac_sha3_256(key, &[1]);
    msg.chunks(KEY_SIZE)
        .enumerate()
        .flat_map(|(i, ci)| xor_unchecked(ci, &hmac_sha3_256(&encryption_key, &to_bytes(i))))
        .collect()
}

/**
 * 计算关联数据和密文的MAC值
 *
 * 使用HMAC-SHA3-256计算AAD和密文的认证码，确保数据完整性和真实性。
 *
 * 参数:
 * @param key - 32字节主密钥
 * @param aad - 关联数据
 * @param ciphertext - 密文
 *
 * 返回:
 * 32字节MAC值
 *
 * 注意: AAD的长度作为前缀添加，以确保输入的唯一性。
 */
fn compute_mac(key: &[u8; KEY_SIZE], aad: &[u8], ciphertext: &[u8]) -> [u8; KEY_SIZE] {
    // Derive MAC key
    let mac_key = hmac_sha3_256(key, &[2]);

    // The length of the aad may vary, so add the length as a prefix to ensure uniqueness of the input.
    hmac_sha3_256(&mac_key, &[&to_bytes(aad.len()), aad, ciphertext].concat())
}

/**
 * HMAC-SHA3-256函数的便捷封装
 *
 * 计算给定密钥和数据的HMAC-SHA3-256值。
 *
 * 参数:
 * @param key - 32字节密钥
 * @param data - 要计算HMAC的数据
 *
 * 返回:
 * 32字节HMAC值
 */
fn hmac_sha3_256(key: &[u8; KEY_SIZE], data: &[u8]) -> [u8; KEY_SIZE] {
    fastcrypto::hmac::hmac_sha3_256(
        &HmacKey::from_bytes(key).expect("Never fails for 32 byte input"),
        data,
    )
    .digest
}

/**
 * 将数字转换为字节数组
 * 
 * 使用BCS序列化将数字转换为固定格式的字节序列。
 * 
 * 参数:
 * @param n - 要转换的数值
 * 
 * 返回:
 * 序列化后的字节数组
 */
fn to_bytes(n: usize) -> Vec<u8> {
    bcs::to_bytes(&(n as u64)).expect("Never fails")
}

#[cfg(test)]
mod tests {
    use crate::dem::{Aes256Gcm, Hmac256Ctr};
    use crate::{utils::generate_random_bytes, KEY_SIZE};
    use rand::thread_rng;

    /// 测试用的示例消息
    const TEST_MSG: &[u8] = b"The difference between a Miracle and a Fact is exactly the difference between a mermaid and a seal.";
    /// 测试用的示例关联数据
    const TEST_AAD: &[u8] = b"Mark Twain";

    /// 测试AES-GCM的基本加密和解密功能
    /// 验证加密后再解密可以恢复原始消息
    #[test]
    fn test_aes_gcm() {
        // 生成随机密钥
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        
        // 加密消息
        let ciphertext = Aes256Gcm::encrypt(TEST_MSG, TEST_AAD, &key);
        
        // 解密并验证结果
        let decrypted = Aes256Gcm::decrypt(&ciphertext, TEST_AAD, &key).unwrap();
        assert_eq!(TEST_MSG, decrypted.as_slice());
    }

    /// 测试AES-GCM在AAD不匹配情况下的失败处理
    /// 验证当修改了AAD时，解密应当失败
    #[test]
    fn test_aes_gcm_fail() {
        // 生成随机密钥
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let msg = b"Hello, world!";
        let aad = b"something";
        
        // 加密消息
        let ciphertext = Aes256Gcm::encrypt(msg, aad, &key);

        // 使用相同AAD可以正常解密
        assert_eq!(
            msg,
            Aes256Gcm::decrypt(&ciphertext, b"something", &key)
                .unwrap()
                .as_slice()
        );
        
        // 使用不同的AAD应该解密失败
        assert!(Aes256Gcm::decrypt(&ciphertext, b"something else", &key).is_err());
    }

    /// AES-GCM的回归测试
    /// 使用固定的密钥和输入，确保加密结果与预期一致
    /// 这有助于检测代码更改是否影响了AES-GCM的行为
    #[test]
    fn regression_test_aes_gcm() {
        // 使用固定的测试密钥
        let key: [u8; KEY_SIZE] =
            hex::decode("43041389faab1f789fa56722b1def4c3ec6da22675e9bd8ad7329cd931bc840a")
                .unwrap()
                .try_into()
                .unwrap();
                
        // 预期的密文
        let ciphertext: Vec<u8> = hex::decode("a3a5c857ee27937f43ccfb42b41ca2155c9a4a77a8e54af35f78a78ff102206142d1be22dfc39a6374463255934ae640adceeffb17e56b9190d8c5f6456e9e7ff1c4eaa45114b640b407efd371f26b1f7d7e48bd86d742a01c0ad7dbe18b86df188e27cb029978b7fd243d9a63bdabd76aa478").unwrap();
        
        // 验证解密结果
        assert_eq!(
            TEST_MSG,
            Aes256Gcm::decrypt(&ciphertext, TEST_AAD, &key)
                .unwrap()
                .as_slice()
        );
        
        // 验证加密结果
        assert_eq!(Aes256Gcm::encrypt(TEST_MSG, TEST_AAD, &key), ciphertext);
    }

    /// 测试HMAC-CTR的基本加密和解密功能
    /// 验证加密后再解密可以恢复原始消息
    #[test]
    fn test_hmac_ctr() {
        // 生成随机密钥
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        
        // 加密消息
        let (ciphertext, mac) = Hmac256Ctr::encrypt(TEST_MSG, TEST_AAD, &key);
        
        // 解密并验证结果
        let decrypted = Hmac256Ctr::decrypt(&ciphertext, &mac, TEST_AAD, &key).unwrap();
        assert_eq!(TEST_MSG, decrypted.as_slice());
    }

    /// 测试HMAC-CTR在AAD不匹配情况下的失败处理
    /// 验证当修改了AAD时，解密应当失败
    #[test]
    fn test_hmac_ctr_fail() {
        // 生成随机密钥
        let mut rng = thread_rng();
        let key = generate_random_bytes(&mut rng);
        let msg = b"Hello, world!";
        let aad = b"something";
        
        // 加密消息
        let (ciphertext, mac) = Hmac256Ctr::encrypt(msg, aad, &key);
        
        // 使用相同AAD可以正常解密
        assert_eq!(
            msg,
            Hmac256Ctr::decrypt(&ciphertext, &mac, b"something", &key)
                .unwrap()
                .as_slice()
        );
        
        // 使用不同的AAD应该解密失败
        assert!(Hmac256Ctr::decrypt(&ciphertext, &mac, b"something else", &key).is_err());
    }

    /// HMAC-CTR的回归测试
    /// 使用固定的密钥和输入，确保加密结果与预期一致
    /// 这有助于检测代码更改是否影响了HMAC-CTR的行为
    #[test]
    fn regression_test_hmac_ctr() {
        // 使用固定的测试密钥
        let key: [u8; KEY_SIZE] =
            hex::decode("5bfdfd7c814903f1311bebacfffa3c001cbeb1cbb3275baa9aafe21fadd9f396")
                .unwrap()
                .try_into()
                .unwrap();
                
        // 预期的密文
        let ciphertext: Vec<u8> = hex::decode("b0c4eee6fbd97a2fb86bbd1e0dafa47d2ce5c9e8975a50c2d9eae02ebede8fee6b6434e68584be475b89089fce4c451cbd4c0d6e00dbcae1241abaf237df2eccdd86b890d35e4e8ae9418386012891d8413483d64179ce1d7fe69ad25d546495df54a1").unwrap();
        let mac: [u8; KEY_SIZE] =
            hex::decode("5de3ffdd9d7a258e651ebdba7d80839df2e19ea40cd35b6e1b06375181a0c2f2")
                .unwrap()
                .try_into()
                .unwrap();
                
        // 验证解密结果
        assert_eq!(
            TEST_MSG,
            Hmac256Ctr::decrypt(&ciphertext, &mac, TEST_AAD, &key)
                .unwrap()
                .as_slice()
        );
        
        // 验证加密结果
        assert_eq!(
            Hmac256Ctr::encrypt(TEST_MSG, TEST_AAD, &key),
            (ciphertext, mac)
        );
    }
}
