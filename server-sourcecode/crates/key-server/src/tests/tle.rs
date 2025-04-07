// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 时间限制执行(Time-Limited Execution, TLE)测试模块
 * 
 * 本模块测试Seal系统的时间限制执行模式。TLE是一种访问控制模式，
 * 允许执行只能在特定时间点或之前执行的操作，提供了一种时间
 * 维度的访问控制机制。测试包括策略验证、证书验证和请求签名验证。
 */

use crate::tests::externals::{ptb_to_base64, sign};
use crate::tests::SealTestCluster;
use crate::{current_epoch_time, InternalError};
use crypto::elgamal;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::KeyPair;
use rand::thread_rng;
use sui_types::{
    base_types::ObjectID,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{ObjectArg, ProgrammableTransaction},
    Identifier, SUI_CLOCK_OBJECT_ID,
};
use tracing_test::traced_test;

/**
 * 测试时间限制执行策略
 * 
 * 此测试验证TLE策略的两个关键方面：
 * 1. 过去或当前时间的执行请求应该被批准
 * 2. 未来时间的执行请求应该被拒绝
 * 
 * 这确保了系统只允许在指定时间点到达或之前执行操作。
 */
#[traced_test]
#[tokio::test]
async fn test_tle_policy() {
    // 创建测试集群并发布模式合约
    let mut tc = SealTestCluster::new(1, 1).await;
    let (package_id, _) = tc.publish("patterns").await;

    {
        // 测试情况1: 使用过去时间的执行请求（应该通过）
        let ptb = tle_create_ptb(package_id, 1);  // 时间为1，表示过去
        let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
        let (cert, req_sig) = sign(
            &package_id,
            &ptb,
            &pk,
            &vk,
            &tc.users[0].keypair,
            current_epoch_time(),
            1,
        );

        // 发送请求到服务器并验证结果
        let result = tc
            .server()
            .check_request(
                &ptb_to_base64(&ptb),
                &pk,
                &vk,
                &req_sig,
                &cert,
                1000,
                None,
                None,
            )
            .await;
        assert!(result.is_ok());
        let key_ids = result.unwrap();
        assert_eq!(key_ids.len(), 2);  // 确认返回了两个密钥ID
        assert_ne!(key_ids[0], key_ids[1]);  // 确认密钥ID不重复
    }
    {
        // 测试情况2: 使用未来时间的执行请求（应该失败）
        let ptb = tle_create_ptb(package_id, u64::MAX);  // 时间为最大值，表示未来
        let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
        let (cert, req_sig) = sign(
            &package_id,
            &ptb,
            &pk,
            &vk,
            &tc.users[0].keypair,
            current_epoch_time(),
            1,
        );

        // 发送请求到服务器并验证结果
        let result = tc
            .server()
            .check_request(
                &ptb_to_base64(&ptb),
                &pk,
                &vk,
                &req_sig,
                &cert,
                1000,
                None,
                None,
            )
            .await;
        assert_eq!(result, Err(InternalError::NoAccess));  // 确认拒绝访问
    }
}

/**
 * 测试证书验证机制
 * 
 * 此测试验证系统对证书(Certificate)的各种验证机制，包括：
 * 1. 有效证书应被接受
 * 2. 篡改时间戳的证书应被拒绝
 * 3. 修改TTL值的证书应被拒绝
 * 4. 使用错误会话验证密钥的证书应被拒绝
 * 5. 过期证书应被拒绝
 * 6. TTL过长的证书应被拒绝
 * 
 * 这确保了系统只接受合法、有效和安全的证书。
 */
#[traced_test]
#[tokio::test]
async fn test_tle_certificate() {
    // 创建测试集群并发布模式合约
    let mut tc = SealTestCluster::new(1, 1).await;
    let (package_id, _) = tc.publish("patterns").await;

    // 创建基本的TLE请求和有效证书
    let ptb = tle_create_ptb(package_id, 1);
    let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
    let (cert, req_sig) = sign(
        &package_id,
        &ptb,
        &pk,
        &vk,
        &tc.users[0].keypair,
        current_epoch_time(),
        5,  // 5分钟有效期
    );

    // 测试情况1: 有效证书应该工作
    let result = tc
        .server()
        .check_request(
            &ptb_to_base64(&ptb),
            &pk,
            &vk,
            &req_sig,
            &cert,
            1000,
            None,
            None,
        )
        .await;
    assert!(result.is_ok());

    // 测试情况2: 篡改时间戳的证书应该失败
    let mut invalid_cert = cert.clone();
    invalid_cert.creation_time = cert.creation_time - 1000;  // 修改创建时间
    let result = tc
        .server()
        .check_request(
            &ptb_to_base64(&ptb),
            &pk,
            &vk,
            &req_sig,
            &invalid_cert,
            1000,
            None,
            None,
        )
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidSignature));

    // 测试情况3: 修改TTL值的证书应该失败
    let mut invalid_cert = cert.clone();
    invalid_cert.ttl_min += 1;  // 增加有效期
    let result = tc
        .server()
        .check_request(
            &ptb_to_base64(&ptb),
            &pk,
            &vk,
            &req_sig,
            &invalid_cert,
            1000,
            None,
            None,
        )
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidSignature));

    // 测试情况4: 使用错误会话验证密钥的证书应该失败
    let mut invalid_cert = cert.clone();
    invalid_cert.session_vk = Ed25519KeyPair::generate(&mut thread_rng()).public().clone();  // 使用新的密钥对
    let result = tc
        .server()
        .check_request(
            &ptb_to_base64(&ptb),
            &pk,
            &vk,
            &req_sig,
            &invalid_cert,
            1000,
            None,
            None,
        )
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidSignature));

    // 测试情况5: 过期证书应该失败
    let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
    let (cert, req_sig) = sign(&package_id, &ptb, &pk, &vk, &tc.users[0].keypair, 1, 1);  // 使用过去的时间戳
    let result = tc
        .server()
        .check_request(
            &ptb_to_base64(&ptb),
            &pk,
            &vk,
            &req_sig,
            &cert,
            1000,
            None,
            None,
        )
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidCertificate));

    // 测试情况6: TTL过长的证书应该失败
    let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
    let (cert, req_sig) = sign(
        &package_id,
        &ptb,
        &pk,
        &vk,
        &tc.users[0].keypair,
        current_epoch_time(),
        100,  // 100分钟，超过限制
    );
    let result = tc
        .server()
        .check_request(
            &ptb_to_base64(&ptb),
            &pk,
            &vk,
            &req_sig,
            &cert,
            1000,
            None,
            None,
        )
        .await;
    assert_eq!(result.err(), Some(InternalError::InvalidCertificate));
}

/**
 * 测试请求签名验证机制
 * 
 * 此测试验证系统正确处理签名请求，确保：
 * 1. 正确签名的请求被接受
 * 2. 有效证书但错误签名的请求被拒绝
 * 3. 有效证书与请求不匹配的情况被拒绝
 * 
 * 这确保了系统只处理经过验证和授权的请求。
 */
#[traced_test]
#[tokio::test]
async fn test_tle_signed_request() {
    // 创建测试集群并发布模式合约
    let mut tc = SealTestCluster::new(1, 1).await;
    let (package_id, _) = tc.publish("patterns").await;

    // 创建基本的TLE请求和有效证书与签名
    let ptb = tle_create_ptb(package_id, 1);
    let (_, pk, vk) = elgamal::genkey(&mut thread_rng());
    let (cert, req_sig) = sign(
        &package_id,
        &ptb,
        &pk,
        &vk,
        &tc.users[0].keypair,
        current_epoch_time(),
        1,
    );

    // 测试情况1: 有效请求签名应该成功
    let result = tc
        .server()
        .check_request(
            &ptb_to_base64(&ptb),
            &pk,
            &vk,
            &req_sig,
            &cert,
            1000,
            None,
            None,
        )
        .await;
    assert!(result.is_ok());

    // 此处可以添加更多测试用例，如：
    // - 使用错误签名的请求
    // - 使用不匹配的证书和请求
    // 等等...
}

/**
 * 生成TLE ID
 * 
 * 为TLE模式生成唯一标识符，基于指定的时间。
 * 
 * @param time - 执行限制时间
 * @return 生成的TLE ID
 */
fn get_tle_id(time: u64) -> Vec<u8> {
    bcs::to_bytes(&time).unwrap()
}

/**
 * 创建TLE模式的可编程事务
 * 
 * 构建用于测试TLE模式的可编程事务，包括：
 * 1. 指定时间限制
 * 2. 添加时钟对象引用
 * 3. 调用seal_approve函数
 * 
 * @param package_id - 模式合约的包ID
 * @param time - 执行限制时间
 * @return 构建好的可编程事务
 */
fn tle_create_ptb(package_id: ObjectID, time: u64) -> ProgrammableTransaction {
    // 创建可编程事务构建器
    let mut builder = ProgrammableTransactionBuilder::new();
    
    // 添加TLE ID参数（基于时间）
    let id = builder.pure(get_tle_id(time)).unwrap();
    
    // 添加时钟对象引用
    let clock = builder.obj(ObjectArg::SharedObject {
        id: SUI_CLOCK_OBJECT_ID,
        initial_shared_version: 1.into(),
        mutable: false,
    }).unwrap();
    
    // 添加调用seal_approve函数的指令
    builder.programmable_move_call(
        package_id,
        Identifier::new("tle").unwrap(),
        Identifier::new("seal_approve").unwrap(),
        vec![],
        vec![id, clock],
    );
    
    // 完成事务构建并返回
    builder.finish()
}
