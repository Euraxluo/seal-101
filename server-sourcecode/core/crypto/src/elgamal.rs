// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * ElGamal加密模块
 * 
 * 本模块实现了基于椭圆曲线的ElGamal加密算法。ElGamal是一种公钥加密系统，
 * 基于离散对数问题的难解性，在密钥服务器和客户端之间的安全通信中被使用。
 * 
 * 主要功能:
 * 1. 密钥对生成 - 创建公钥、私钥和验证密钥
 * 2. 消息加密 - 使用接收者的公钥加密消息
 * 3. 消息解密 - 使用私钥解密密文
 * 
 * 该实现是通用的，可以与任何满足GroupElement接口的群一起使用，
 * 比如椭圆曲线群。
 */

use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};

/// ElGamal私钥
/// 由群G的标量元素组成
#[derive(Serialize, Deserialize)]
pub struct SecretKey<G: GroupElement>(G::ScalarType);

/// ElGamal公钥
/// 由群G的元素组成，等于生成元乘以私钥
#[derive(Serialize, Deserialize)]
pub struct PublicKey<G: GroupElement>(G);

/// 验证密钥
/// 用于验证密钥持有证明，与公钥使用相同的私钥但不同的生成元
#[derive(Serialize, Deserialize)]
pub struct VerificationKey<G: GroupElement>(G);

/// ElGamal加密结果
/// 包含两个群元素：(c1, c2)
/// 其中c1 = g^r，c2 = pk^r + m
/// r是随机数，m是明文消息，pk是接收者的公钥
#[derive(Serialize, Deserialize)]
pub struct Encryption<G: GroupElement>(pub G, pub G);

/**
 * 生成ElGamal密钥对
 * 
 * 创建一个由私钥、公钥和验证密钥组成的密钥对。
 * 公钥和验证密钥都是通过私钥乘以各自群的生成元得到的。
 * 
 * 参数:
 * @param rng - 随机数生成器
 * 
 * 返回:
 * 包含私钥、公钥和验证密钥的元组
 */
pub fn genkey<G: GroupElement, VG: GroupElement<ScalarType = G::ScalarType>, R: AllowedRng>(
    rng: &mut R,
) -> (SecretKey<G>, PublicKey<G>, VerificationKey<VG>) {
    let sk = G::ScalarType::rand(rng);
    (
        SecretKey(sk),
        PublicKey(G::generator() * sk),
        VerificationKey(VG::generator() * sk),
    )
}

/**
 * 使用接收者的公钥加密消息
 * 
 * 实现ElGamal加密算法：
 * 1. 生成随机数r
 * 2. 计算c1 = g^r
 * 3. 计算c2 = pk^r + m，其中pk是接收者的公钥，m是明文消息
 * 
 * 参数:
 * @param rng - 随机数生成器
 * @param msg - 要加密的明文消息（群元素）
 * @param pk - 接收者的公钥
 * 
 * 返回:
 * 加密结果，包含两个群元素(c1, c2)
 */
pub fn encrypt<G: GroupElement, R: AllowedRng>(
    rng: &mut R,
    msg: &G,
    pk: &PublicKey<G>,
) -> Encryption<G> {
    let r = G::ScalarType::rand(rng);
    Encryption(G::generator() * r, pk.0 * r + msg)
}

/**
 * 使用私钥解密密文
 * 
 * 实现ElGamal解密算法：
 * 计算m = c2 - sk * c1，其中(c1, c2)是密文，sk是私钥
 * 
 * 参数:
 * @param sk - 接收者的私钥
 * @param e - 要解密的密文
 * 
 * 返回:
 * 解密后的明文消息（群元素）
 */
pub fn decrypt<G: GroupElement>(sk: &SecretKey<G>, e: &Encryption<G>) -> G {
    e.1 - e.0 * sk.0
}
