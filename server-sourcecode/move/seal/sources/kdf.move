// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 密钥派生函数(KDF)模块
 * 
 * 该模块实现了基于HKDF-SHA3-256的密钥派生函数，用于从IBE中的配对结果生成对称加密密钥。
 * KDF确保从配对操作生成的元素可以安全地转换为固定长度的对称密钥。
 * 
 * 主要功能:
 * - 将IBE配对结果转换为对称加密密钥
 * - 结合额外的上下文信息(nonce, gid, object_id, index)增强安全性
 * - 基于HMAC-SHA3-256的HKDF实现
 */
module seal::kdf;

use sui::{bls12381::{G1, G2, GT}, group_ops::Element, hmac::hmac_sha3_256};

/**
 * 从IBE配对结果派生对称密钥
 * 
 * 该函数将IBE配对操作的结果与其他上下文信息结合，派生出一个对称密钥。
 * 使用HKDF-SHA3-256算法，确保派生的密钥具有良好的密码学特性。
 * 
 * 参数:
 * @param input - GT元素，通常是IBE配对操作的结果
 * @param nonce - G2元素，用于增加随机性
 * @param gid - G1元素，通常是身份哈希值
 * @param object_id - 对象的地址标识符
 * @param index - 密钥索引，用于在多密钥环境中区分不同密钥
 * 
 * 返回:
 * 派生的对称密钥字节数组
 */
public(package) fun kdf(
    input: &Element<GT>,
    nonce: &Element<G2>,
    gid: &Element<G1>,
    object_id: address,
    index: u8,
): vector<u8> {
    // 组合所有输入材料
    let mut bytes = *input.bytes();
    bytes.append(*nonce.bytes());
    bytes.append(*gid.bytes());

    // 组合信息字段
    let mut info = object_id.to_bytes();
    info.push_back(index);

    // 调用HKDF函数
    hkdf_sha3_256(
        &bytes,  // 输入密钥材料(IKM)
        &x"0000000000000000000000000000000000000000000000000000000000000000",  // 盐值(32字节的0)
        &info,   // 信息字段
    )
}

/**
 * HKDF-SHA3-256实现
 * 
 * 基于RFC5869的HKDF算法简化版本，使用SHA3-256作为哈希函数。
 * 此实现固定输出长度为32字节，适用于生成AES密钥等场景。
 * 
 * 参数:
 * @param ikm - 输入密钥材料
 * @param salt - 盐值，必须非空
 * @param info - 可选的应用特定信息
 * 
 * 返回:
 * 派生的密钥材料(32字节)
 */
fun hkdf_sha3_256(ikm: &vector<u8>, salt: &vector<u8>, info: &vector<u8>): vector<u8> {
    assert!(!salt.is_empty());
    
    // 只实现了HKDF的第一次迭代，生成32字节输出
    let mut t = *info;
    t.push_back(1);  // 计数器，标识第一个输出块
    
    // 两步HKDF过程:
    // 1. 使用盐提取(extract)随机材料: PRK = HMAC(salt, IKM)
    // 2. 使用PRK扩展(expand)为所需的输出长度: OKM = HMAC(PRK, info|counter)
    hmac_sha3_256(&hmac_sha3_256(salt, ikm), &t)
}

/**
 * KDF函数的单元测试
 * 
 * 验证KDF函数使用已知输入生成预期输出
 */
#[test]
fun test_kdf() {
    use sui::bls12381::{scalar_from_u64, g2_generator, gt_generator, g2_mul, hash_to_g1, gt_mul};
    // 创建测试输入
    let r = scalar_from_u64(12345u64);
    let x = gt_mul(&r, &gt_generator());
    let nonce = g2_mul(&r, &g2_generator());
    let gid = hash_to_g1(&vector[0]);
    
    // 计算派生密钥
    let derived_key = kdf(&x, &nonce, &gid, @0x0, 42);
    
    // 验证结果
    let expected = x"1963b93f076d0dc97cbb38c3864b2d6baeb87c7eb99139100fd775b0b09f668b";
    assert!(derived_key == expected);
}
