// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 白名单(Whitelist)访问控制模式测试模块
 * 
 * 本模块测试Seal系统的白名单访问控制功能。白名单是一种访问控制模式，
 * 允许管理员明确指定哪些用户可以访问特定资源，只有在白名单中的用户
 * 才能获取密钥，从而访问加密资源。
 */

use super::externals::get_key;
use crate::tests::SealTestCluster;
use serde_json::json;
use sui_sdk::{json::SuiJsonValue, rpc_types::ObjectChange};
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{ObjectArg, ProgrammableTransaction},
    Identifier,
};
use test_cluster::TestCluster;
use tracing_test::traced_test;

/**
 * 测试基本白名单功能
 * 
 * 此测试验证：
 * 1. 创建白名单并添加用户
 * 2. 白名单中的用户可以获取密钥
 * 3. 不在白名单中的用户无法获取密钥
 */
#[traced_test]
#[tokio::test]
async fn test_whitelist() {
    // 创建测试集群，包含1个密钥服务器和2个用户
    let mut tc = SealTestCluster::new(1, 2).await;

    // 发布示例模式合约
    let (package_id, _) = tc.publish("patterns").await;

    // 创建白名单及其管理权限
    let (whitelist, cap) = create_whitelist(tc.get_mut(), package_id).await;

    // 将第一个用户添加到白名单
    let user_address = tc.users[0].address;
    add_user_to_whitelist(tc.get_mut(), package_id, whitelist, cap, user_address).await;

    // 获取白名单对象当前的共享版本号
    let initial_shared_version = 3;

    // 测试用例1: 白名单中的用户应该可以获取密钥
    let ptb = whitelist_create_ptb(package_id, whitelist, initial_shared_version);
    assert!(
        get_key(tc.server(), &package_id, ptb.clone(), &tc.users[0].keypair)
            .await
            .is_ok()
    );
    
    // 测试用例2: 不在白名单中的用户应该无法获取密钥
    assert!(get_key(tc.server(), &package_id, ptb, &tc.users[1].keypair)
        .await
        .is_err());

    // 再次验证第二个用户无法获取密钥
    let ptb = whitelist_create_ptb(package_id, whitelist, initial_shared_version);
    assert!(get_key(tc.server(), &package_id, ptb, &tc.users[1].keypair)
        .await
        .is_err());
}

/**
 * 测试包升级后的白名单功能
 * 
 * 此测试验证包升级后的白名单访问行为：
 * 1. 升级后的最新包版本应该被允许访问
 * 2. 旧版本的包应该被拒绝访问
 * 
 * 这确保了系统能够正确处理包升级，并强制用户使用最新版本的包。
 */
#[traced_test]
#[tokio::test]
async fn test_whitelist_with_upgrade() {
    // 创建测试集群，包含1个密钥服务器和1个用户
    let mut tc = SealTestCluster::new(1, 1).await;

    // 发布第一个版本的模式合约
    let (package_id_1, upgrade_cap) = tc.publish("patterns").await;
    println!("Old pkg: {}", package_id_1);

    // 创建白名单并添加用户
    let (whitelist, cap) = create_whitelist(tc.get_mut(), package_id_1).await;
    let user_address = tc.users[0].address;
    add_user_to_whitelist(tc.get_mut(), package_id_1, whitelist, cap, user_address).await;

    // 获取白名单对象当前的共享版本号
    let initial_shared_version = 3;

    // 测试用例1: 使用初始版本包应该成功
    let ptb = whitelist_create_ptb(package_id_1, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_ok());

    // 升级包到第二个版本
    let package_id_2 = tc.upgrade(package_id_1, upgrade_cap, "patterns").await;

    // 测试用例2: 使用新包ID应该成功
    let ptb = whitelist_create_ptb(package_id_2, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_ok());

    // 测试用例3: 但使用旧包ID应该失败
    let ptb = whitelist_create_ptb(package_id_1, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_err());

    // 再次升级包到第三个版本
    let package_id_3 = tc.upgrade(package_id_2, upgrade_cap, "patterns").await;

    // 测试用例4: 使用最新包ID应该成功
    let ptb = whitelist_create_ptb(package_id_3, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_ok());

    // 测试用例5: 使用中间版本包ID应该失败
    let ptb = whitelist_create_ptb(package_id_2, whitelist, initial_shared_version);
    assert!(get_key(
        tc.server(),
        &package_id_1,
        ptb.clone(),
        &tc.users[0].keypair
    )
    .await
    .is_err());
}

// 此处有一个被注释掉的测试，原计划用于测试白名单路由器，暂未实现

/**
 * 创建白名单访问请求的可编程事务
 * 
 * 构建用于请求访问白名单资源的可编程事务，此事务将被发送到密钥服务器
 * 以验证用户是否在白名单中。
 * 
 * @param package_id - 模式合约的包ID
 * @param whitelist_id - 白名单对象ID
 * @param initial_shared_version - 白名单对象的共享版本号
 * @return 构建好的可编程事务
 */
pub fn whitelist_create_ptb(
    package_id: ObjectID,
    whitelist_id: ObjectID,
    initial_shared_version: u64,
) -> ProgrammableTransaction {
    // 创建可编程事务构建器
    let mut builder = ProgrammableTransactionBuilder::new();
    
    // 添加白名单ID参数
    let ids = builder.pure(whitelist_id.to_vec()).unwrap();
    
    // 添加白名单对象引用
    let list = builder
        .obj(ObjectArg::SharedObject {
            id: whitelist_id,
            initial_shared_version: initial_shared_version.into(),
            mutable: false,
        })
        .unwrap();

    // 添加调用seal_approve函数的指令
    builder.programmable_move_call(
        package_id,
        Identifier::new("whitelist").unwrap(),
        Identifier::new("seal_approve").unwrap(),
        vec![],
        vec![ids, list],
    );

    // 完成事务构建并返回
    builder.finish()
}

/**
 * 创建白名单对象
 * 
 * 在测试链上创建一个新的白名单对象及其管理权限对象。
 * 
 * @param cluster - 测试集群实例
 * @param package_id - 模式合约的包ID
 * @return 元组(白名单对象ID, 管理权限对象ID)
 */
pub(crate) async fn create_whitelist(
    cluster: &mut TestCluster,
    package_id: ObjectID,
) -> (ObjectID, ObjectID) {
    // 创建新白名单
    let tx = cluster
        .sui_client()
        .transaction_builder()
        .move_call(
            cluster.get_address_0(),
            package_id,
            "whitelist",
            "create_whitelist_entry",
            vec![],
            vec![],
            None,
            50_000_000,
            None,
        )
        .await
        .unwrap();
    let response = cluster.sign_and_execute_transaction(&tx).await;

    // 从响应中读取白名单和管理权限对象ID
    let mut whitelist: Option<ObjectID> = None;
    let mut cap: Option<ObjectID> = None;
    for created in response.object_changes.unwrap() {
        if let ObjectChange::Created {
            object_type,
            object_id,
            ..
        } = created
        {
            match object_type.name.as_str() {
                "Whitelist" => whitelist.replace(object_id),
                "Cap" => cap.replace(object_id),
                _ => None,
            };
        }
    }
    assert!(whitelist.is_some() && cap.is_some());
    let whitelist = whitelist.unwrap();
    let cap = cap.unwrap();

    (whitelist, cap)
}

/**
 * 将用户添加到白名单
 * 
 * 在测试链上将指定用户添加到白名单中。
 * 
 * @param cluster - 测试集群实例
 * @param package_id - 模式合约的包ID
 * @param whitelist - 白名单对象ID
 * @param cap - 白名单管理权限对象ID
 * @param user - 要添加的用户地址
 */
pub(crate) async fn add_user_to_whitelist(
    cluster: &mut TestCluster,
    package_id: ObjectID,
    whitelist: ObjectID,
    cap: ObjectID,
    user: SuiAddress,
) {
    // 构建并执行添加用户到白名单的事务
    let tx = cluster
        .sui_client()
        .transaction_builder()
        .move_call(
            cluster.get_address_0(),
            package_id,
            "whitelist",
            "add",
            vec![],
            vec![
                SuiJsonValue::from_object_id(whitelist),
                SuiJsonValue::from_object_id(cap),
                SuiJsonValue::new(json!(user.to_string())).unwrap(),
            ],
            None,
            50_000_000,
            None,
        )
        .await
        .unwrap();
    let response = cluster.sign_and_execute_transaction(&tx).await;
    assert!(response.status_ok().unwrap());
}
