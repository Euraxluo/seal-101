// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 端到端(E2E)测试模块
 * 
 * 本模块实现了密钥服务器系统的完整端到端测试，
 * 验证从密钥服务器注册、用户请求密钥、加密到解密的整个流程。
 */

use crate::tests::externals::get_key;
use crate::tests::whitelist::{add_user_to_whitelist, create_whitelist, whitelist_create_ptb};
use crate::tests::SealTestCluster;
use crypto::{seal_decrypt, seal_encrypt, EncryptionInput, IBEPublicKeys, IBEUserSecretKeys};
use tracing_test::traced_test;

/**
 * 完整的端到端流程测试
 * 
 * 此测试验证以下流程:
 * 1. 创建测试集群并发布必要的智能合约
 * 2. 创建和配置白名单
 * 3. 从多个密钥服务器获取用户密钥
 * 4. 在链上注册密钥服务器
 * 5. 使用Seal系统加密消息
 * 6. 使用获取的用户密钥解密消息
 * 7. 验证解密结果是否与原始消息一致
 */
#[traced_test]
#[tokio::test]
async fn test_e2e() {
    // 创建测试集群，包含3个密钥服务器和1个用户
    let mut tc = SealTestCluster::new(3, 1).await;
    
    // 发布示例合约，获取包ID
    let (examples_package_id, _) = tc.publish("patterns").await;

    // 创建白名单及其管理权限
    let (whitelist, cap) = create_whitelist(tc.get_mut(), examples_package_id).await;

    // 添加测试用户到白名单
    let user_address = tc.users[0].address;
    add_user_to_whitelist(
        tc.get_mut(),
        examples_package_id,
        whitelist,
        cap,
        user_address,
    )
    .await;

    // 记录当前共享版本号，用于构建PTB
    let initial_shared_version = 3;

    // 创建用于请求密钥的可编程事务
    let ptb = whitelist_create_ptb(examples_package_id, whitelist, initial_shared_version);

    // 向两个不同的密钥服务器发送请求，获取用户密钥
    // 从第一个密钥服务器获取密钥
    let usk0 = get_key(
        &tc.servers[0].server,
        &examples_package_id,
        ptb.clone(),
        &tc.users[0].keypair,
    )
    .await
    .unwrap();
    
    // 从第二个密钥服务器获取密钥
    let usk1 = get_key(
        &tc.servers[1].server,
        &examples_package_id,
        ptb,
        &tc.users[0].keypair,
    )
    .await
    .unwrap();

    // 发布Seal核心合约并获取包ID
    let (package_id, _) = tc.publish("seal").await;

    // 在链上注册所有三个密钥服务器
    let mut services = vec![];
    for i in 0..3 {
        services.push(
            tc.register_key_server(
                package_id,
                &format!("Test server {}", i),  // 服务器描述
                &format!("https:://testserver{}.com", i),  // 服务器URL
                tc.servers[i].public_key,  // 服务器公钥
            )
            .await,
        );
    }

    // 从链上读取注册的密钥服务器公钥，并验证是否与预期一致
    let pks = tc.get_public_keys(&services).await;
    assert_eq!(
        pks,
        tc.servers.iter().map(|s| s.public_key).collect::<Vec<_>>()
    );
    
    // 封装公钥为IBE公钥格式
    let pks = IBEPublicKeys::BonehFranklinBLS12381(pks);

    // 准备要加密的测试消息
    let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
    let services = services.to_vec();
    
    // 使用Seal系统加密消息
    // 阈值设为2，表示至少需要2个密钥服务器的密钥才能解密
    let encryption = seal_encrypt(
        examples_package_id,  // 使用示例包ID作为包标识
        whitelist.to_vec(),   // 白名单ID作为消息ID
        services.clone(),     // 密钥服务器对象ID列表
        &pks,                 // 密钥服务器公钥列表
        2,                    // 阈值设为2
        EncryptionInput::Aes256Gcm {  // 使用AES-GCM加密模式
            data: message.to_vec(),    // 要加密的消息
            aad: None,                 // 无额外认证数据
        },
    )
    .unwrap()
    .0;

    // 使用前两个服务器提供的用户密钥解密消息
    let decryption = seal_decrypt(
        &encryption,  // 加密对象
        &IBEUserSecretKeys::BonehFranklinBLS12381(services.into_iter().zip([usk0, usk1]).collect()),  // 用户密钥
        Some(&pks),   // 提供公钥以验证份额一致性
    )
    .unwrap();

    // 验证解密结果是否与原始消息一致
    assert_eq!(decryption, message);
}
