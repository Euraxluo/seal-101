// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 外部接口测试模块
 * 
 * 本模块包含与密钥服务器外部接口交互的测试工具函数，
 * 主要用于创建、签名和发送请求到密钥服务器，以及处理响应。
 */

use crate::externals::current_epoch_time;
use crate::signed_message::signed_request;
use crate::{
    signed_message,
    types::{ElGamalPublicKey, ElgamalVerificationKey},
    Certificate, Server,
};
use crypto::elgamal;
use fastcrypto::ed25519::Ed25519Signature;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::traits::{KeyPair, Signer};
use fastcrypto::{ed25519::Ed25519KeyPair, error::FastCryptoResult, groups::bls12381::G1Element};
use rand::thread_rng;
use shared_crypto::intent::{Intent, IntentMessage, PersonalMessage};
use sui_types::{
    base_types::ObjectID, crypto::Signature, signature::GenericSignature,
    transaction::ProgrammableTransaction,
};

/**
 * 将可编程事务转换为Base64编码的字符串
 * 
 * 用于将事务序列化并编码，以便通过网络传输或存储
 * 
 * @param ptb - 要编码的可编程事务
 * @return 事务的Base64编码字符串
 */
pub(super) fn ptb_to_base64(ptb: &ProgrammableTransaction) -> String {
    Base64::encode(bcs::to_bytes(ptb).unwrap())
}

/**
 * 为请求生成证书和签名
 * 
 * 此函数创建两个关键组件：
 * 1. 证书(Certificate) - 用于验证用户身份和会话合法性
 * 2. 请求签名 - 用于验证特定请求的真实性
 * 
 * @param pkg_id - 包ID，标识密钥服务器使用的Move包
 * @param ptb - 要签名的可编程事务
 * @param eg_pk - ElGamal公钥，用于加密通信
 * @param eg_vk - ElGamal验证密钥，用于验证加密数据
 * @param kp - 用户的Ed25519密钥对，用于签名
 * @param creation_time - 证书创建时间戳（Unix时间戳）
 * @param ttl_min - 证书有效期（分钟）
 * @return 包含证书和请求签名的元组
 */
pub(super) fn sign(
    pkg_id: &ObjectID,
    ptb: &ProgrammableTransaction,
    eg_pk: &ElGamalPublicKey,
    eg_vk: &ElgamalVerificationKey,
    kp: &Ed25519KeyPair,
    creation_time: u64,
    ttl_min: u16,
) -> (Certificate, Ed25519Signature) {
    // 为证书和请求签名使用相同的EdDSA密钥对

    // 创建证书
    let msg_to_sign = signed_message::signed_message(pkg_id, kp.public(), creation_time, ttl_min);
    let personal_msg = PersonalMessage {
        message: msg_to_sign.as_bytes().to_vec(),
    };
    let msg_with_intent = IntentMessage::new(Intent::personal_message(), personal_msg.clone());
    let cert_sig = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, kp));
    let cert = Certificate {
        user: kp.public().into(),
        session_vk: kp.public().clone(),
        creation_time,
        ttl_min,
        signature: cert_sig,
    };
    
    // 创建会话签名
    let signed_msg = signed_request(ptb, eg_pk, eg_vk);
    let request_sig = kp.sign(&signed_msg);
    (cert, request_sig)
}

/**
 * 从密钥服务器获取密钥
 * 
 * 此函数完成以下步骤：
 * 1. 生成ElGamal密钥对用于加密通信
 * 2. 创建并签名证书和请求
 * 3. 向密钥服务器发送请求
 * 4. 解密服务器响应获取密钥
 * 
 * @param server - 密钥服务器实例
 * @param pkg_id - 包ID，标识密钥服务器使用的Move包
 * @param ptb - 要发送的可编程事务
 * @param kp - 用户的Ed25519密钥对，用于签名
 * @return 成功时返回解密的用户密钥(G1Element)，失败时返回错误
 */
pub(crate) async fn get_key(
    server: &Server,
    pkg_id: &ObjectID,
    ptb: ProgrammableTransaction,
    kp: &Ed25519KeyPair,
) -> FastCryptoResult<G1Element> {
    // 生成ElGamal密钥对用于加密通信
    let (sk, pk, vk) = elgamal::genkey(&mut thread_rng());
    
    // 创建证书和请求签名
    let (cert, req_sig) = sign(pkg_id, &ptb, &pk, &vk, kp, current_epoch_time(), 1);
    
    // 向服务器发送请求并处理响应
    server
        .check_request(
            &ptb_to_base64(&ptb),
            &pk,
            &vk,
            &req_sig,
            &cert,
            1000, // 超时毫秒数
            None, // 无额外验证数据
            None, // 无白名单证明
        )
        .await
        .map(|ids| {
            // 解密服务器返回的加密密钥
            elgamal::decrypt(
                &sk,
                &server.create_response(&ids, &pk).decryption_keys[0].encrypted_key,
            )
        })
        .map_err(|_| fastcrypto::error::FastCryptoError::GeneralOpaqueError)
}
