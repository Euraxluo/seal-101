// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 私有数据(PrivateData)访问控制模式测试模块
 * 
 * 本模块测试Seal系统对私有数据对象的访问控制功能。
 * PrivateData是一种模式，允许数据所有者控制谁可以访问数据，
 * 通过密钥服务器验证用户是否有权访问特定的私有数据对象。
 */

use crate::tests::externals::get_key;
use crate::tests::SealTestCluster;
use sui_sdk::{json::SuiJsonValue, rpc_types::ObjectChange};
use sui_types::base_types::{ObjectDigest, SequenceNumber};
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{ObjectArg, ProgrammableTransaction},
    Identifier,
};
use test_cluster::TestCluster;
use tracing_test::traced_test;

/**
 * 测试私有数据访问控制
 * 
 * 此测试验证:
 * 1. 数据所有者可以访问自己的私有数据
 * 2. 非所有者不能访问私有数据
 * 3. 使用错误的nonce不能访问私有数据
 */
#[traced_test]
#[tokio::test]
async fn test_pd() {
    // 创建测试集群，包含1个密钥服务器和2个用户
    let mut tc = SealTestCluster::new(1, 2).await;

    // 发布示例模式合约
    let (package_id, _) = tc.publish("patterns").await;

    // 创建私有数据对象，使用package_id作为nonce，所有者为第一个用户
    let (pd, version, digest) =
        create_private_data(tc.users[0].address, tc.get_mut(), package_id).await;

    // 测试用例1: 所有者应该可以访问
    // 构建访问请求事务
    let ptb = pd_create_ptb(tc.get_mut(), package_id, package_id, pd, version, digest).await;
    // 验证第一个用户(所有者)可以获取密钥
    assert!(
        get_key(tc.server(), &package_id, ptb.clone(), &tc.users[0].keypair)
            .await
            .is_ok()
    );
    
    // 测试用例2: 非所有者不应该可以访问
    // 验证第二个用户(非所有者)无法获取密钥
    assert!(get_key(tc.server(), &package_id, ptb, &tc.users[1].keypair)
        .await
        .is_err());

    // 测试用例3: 使用错误的nonce不能访问
    // 构建使用错误nonce的访问请求事务
    let ptb = pd_create_ptb(
        &mut tc.cluster,
        package_id,
        ObjectID::random(),  // 使用随机ID作为nonce，而不是正确的package_id
        pd,
        version,
        digest,
    )
    .await;
    // 验证即使是所有者，使用错误的nonce也无法获取密钥
    assert!(
        get_key(tc.server(), &package_id, ptb.clone(), &tc.users[0].keypair)
            .await
            .is_err()
    );
}

/**
 * 创建私有数据对象
 * 
 * 此函数执行两个操作:
 * 1. 创建一个新的PrivateData对象
 * 2. 将该对象转移给指定的用户
 * 
 * @param user - 私有数据的目标所有者地址
 * @param cluster - 测试集群实例
 * @param package_id - 模式合约的包ID，也用作nonce
 * @return 元组(私有数据对象ID, 版本号, 对象摘要)，用于后续操作
 */
pub(crate) async fn create_private_data(
    user: SuiAddress,
    cluster: &mut TestCluster,
    package_id: ObjectID,
) -> (ObjectID, SequenceNumber, ObjectDigest) {
    // 创建事务构建器
    let builder = cluster.sui_client().transaction_builder();
    
    // 构建并执行创建私有数据的事务
    let tx = builder
        .move_call(
            cluster.get_address_0(),  // 发送者地址
            package_id,               // 包ID
            "private_data",           // 模块名
            "store_entry",            // 函数名
            vec![],                   // 类型参数
            vec![
                SuiJsonValue::from_object_id(package_id),  // creator参数
                SuiJsonValue::from_object_id(package_id),  // nonce参数
            ],
            None,                     // 无gas币
            50_000_000,               // gas预算
            None,                     // 无gas价格
        )
        .await
        .unwrap();
    let response = cluster.sign_and_execute_transaction(&tx).await;

    // 从响应中找到创建的PrivateData对象ID
    let mut pd: Option<ObjectID> = None;
    for created in response.object_changes.unwrap() {
        if let ObjectChange::Created {
            object_type,
            object_id,
            ..
        } = created
        {
            if object_type.name.as_str() == "PrivateData" {
                pd.replace(object_id);
            };
        }
    }

    // 构建并执行将私有数据转移给用户的事务
    let builder = cluster.sui_client().transaction_builder();
    let tx = builder
        .transfer_object(cluster.get_address_0(), pd.unwrap(), None, 50_000_000, user)
        .await
        .unwrap();
    let response = cluster.sign_and_execute_transaction(&tx).await;
    assert!(response.status_ok().unwrap());
    
    // 从响应中找到修改后的PrivateData对象信息
    for modified in response.object_changes.unwrap() {
        if let ObjectChange::Mutated {
            object_type,
            object_id,
            version,
            digest,
            ..
        } = modified
        {
            if object_type.name.as_str() == "PrivateData" {
                return (object_id, version, digest);
            }
        }
    }

    panic!("should have found the pd object");
}

/**
 * 创建访问私有数据的可编程事务
 * 
 * 构建用于请求访问私有数据的事务，此事务将被发送到密钥服务器
 * 以验证用户是否有权访问特定的私有数据。
 * 
 * @param cluster - 测试集群实例
 * @param package_id - 模式合约的包ID
 * @param nonce - 用于构建数据ID的nonce
 * @param pd - 私有数据对象ID
 * @param version - 私有数据对象版本号
 * @param digest - 私有数据对象摘要
 * @return 构建好的可编程事务
 */
async fn pd_create_ptb(
    cluster: &mut TestCluster,
    package_id: ObjectID,
    nonce: ObjectID,
    pd: ObjectID,
    version: SequenceNumber,
    digest: ObjectDigest,
) -> ProgrammableTransaction {
    // 创建可编程事务构建器
    let mut builder = ProgrammableTransactionBuilder::new();
    
    // 构建数据ID = 创建者地址 || nonce
    let id = [
        bcs::to_bytes(&cluster.get_address_0()).unwrap(),
        bcs::to_bytes(&nonce).unwrap(),
    ]
    .concat();
    let id = builder.pure(id).unwrap();
    
    // 添加私有数据对象参数
    let pd = builder
        .obj(ObjectArg::ImmOrOwnedObject((pd, version, digest)))
        .unwrap();

    // 添加调用seal_approve函数的指令
    builder.programmable_move_call(
        package_id,
        Identifier::new("private_data").unwrap(),
        Identifier::new("seal_approve").unwrap(),
        vec![],
        vec![id, pd],
    );
    
    // 完成事务构建并返回
    builder.finish()
}
