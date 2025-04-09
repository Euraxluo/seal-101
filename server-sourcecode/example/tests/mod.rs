// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 密钥服务器测试模块
 * 
 * 本模块提供了测试密钥服务器功能的框架和工具。它实现了一个测试集群，可以模拟
 * 多个密钥服务器和用户之间的交互，用于验证访问控制、加密解密流程和服务器行为。
 * 
 * 主要测试分为以下几个子模块：
 * - e2e: 端到端测试，验证完整的加密解密流程
 * - externals: 外部接口测试工具函数
 * - pd: 私有数据访问控制模式测试
 * - tle: 时间限制执行模式测试
 * - whitelist: 白名单访问控制模式测试
 * - server: 服务器后台功能和更新机制测试
 */

use crate::externals::{add_latest, add_package};
use crate::types::Network;
use crate::Server;
use crypto::ibe;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::groups::GroupElement;
use fastcrypto::serde_helpers::ToFromByteArray;
use rand::thread_rng;
use serde_json::json;
use std::path::PathBuf;
use std::str::FromStr;
use sui_move_build::BuildConfig;
use sui_sdk::json::SuiJsonValue;
use sui_sdk::rpc_types::{ObjectChange, SuiData, SuiObjectDataOptions};
use sui_types::base_types::{ObjectID, SuiAddress};
use sui_types::crypto::get_key_pair_from_rng;
use sui_types::move_package::UpgradePolicy;
use test_cluster::{TestCluster, TestClusterBuilder};

// 声明子模块
mod e2e;
mod externals;
mod pd;
mod tle;
mod whitelist;
mod server;

/**
 * Seal测试集群结构体
 * 
 * 这是一个对Sui测试集群的包装，添加了Seal密钥服务器特定的功能。
 * 它提供了创建和管理测试集群、密钥服务器和测试用户的方法，以及
 * 部署智能合约、注册密钥服务器和获取公钥等操作。
 */
pub(crate) struct SealTestCluster {
    /// 底层Sui测试集群
    cluster: TestCluster,
    /// 密钥服务器列表
    pub(crate) servers: Vec<SealKeyServer>,
    /// 测试用户列表
    pub(crate) users: Vec<SealUser>,
}

/**
 * Seal密钥服务器结构体
 * 
 * 表示测试环境中的单个密钥服务器，包含服务器实例和对应的IBE公钥。
 */
pub(crate) struct SealKeyServer {
    /// 服务器实例
    server: Server,
    /// 服务器的IBE公钥
    public_key: ibe::PublicKey,
}

/**
 * Seal测试用户结构体
 * 
 * 表示测试环境中的单个用户，包含用户地址和密钥对。
 */
pub(crate) struct SealUser {
    /// 用户的Sui地址
    address: SuiAddress,
    /// 用户的Ed25519密钥对
    keypair: Ed25519KeyPair,
}

impl SealTestCluster {
    /**
     * 创建新的Seal测试集群
     * 
     * 创建一个新的测试集群，其中包含指定数量的密钥服务器和用户。
     * 注意：密钥服务器默认不会自动在链上注册，需要使用register_key_server方法进行注册。
     * 
     * @param servers - 要创建的密钥服务器数量
     * @param users - 要创建的测试用户数量
     * @return 新的SealTestCluster实例
     */
    pub async fn new(servers: usize, users: usize) -> Self {
        // 创建Sui测试集群
        let cluster = TestClusterBuilder::new().build().await;

        let mut rng = thread_rng();

        // 创建密钥服务器
        // 注意：我们可以发布Seal模块并在链上注册密钥服务器，但目前测试不需要这样做，为了加速测试
        let servers = (0..servers)
            .map(|_| ibe::generate_key_pair(&mut rng))
            .map(|(master_key, public_key)| SealKeyServer {
                server: Server {
                    sui_client: cluster.sui_client().clone(),
                    network: Network::TestCluster,
                    master_key,
                    key_server_object_id: ObjectID::ZERO,
                    key_server_object_id_sig: G1Element::generator(),
                },
                public_key,
            })
            .collect();

        // 创建测试用户
        let users = (0..users)
            .map(|_| get_key_pair_from_rng(&mut rng))
            .map(|(address, keypair)| SealUser { address, keypair })
            .collect();

        Self {
            cluster,
            servers,
            users,
        }
    }

    /**
     * 获取底层TestCluster的可变引用
     * 
     * @return 对TestCluster的可变引用
     */
    pub fn get_mut(&mut self) -> &mut TestCluster {
        &mut self.cluster
    }

    /**
     * 获取第一个服务器的引用
     * 
     * 如果没有服务器，此方法会引发panic。
     * 
     * @return 对第一个服务器的引用
     */
    pub fn server(&self) -> &Server {
        &self.servers[0].server
    }

    /**
     * 发布Move模块
     * 
     * 在测试链上发布指定的Move模块，并返回包ID和升级能力ID。
     * 模块路径相对于/move/<module>。
     * 
     * @param module - 要发布的模块名称
     * @return 元组(包ID, 升级能力ID)
     */
    pub async fn publish(&mut self, module: &str) -> (ObjectID, ObjectID) {
        // 构建模块路径
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.extend(["..", "..", "example", module]);
        let compiled_package = BuildConfig::new_for_testing().build(&path).unwrap();

        // 发布包
        let builder = self.cluster.sui_client().transaction_builder();
        let tx = builder
            .publish(
                self.cluster.get_address_0(),
                compiled_package.get_package_bytes(true),
                compiled_package.get_dependency_storage_package_ids(),
                None,
                40_000_000_000,
            )
            .await
            .unwrap();
        let response = self.cluster.sign_and_execute_transaction(&tx).await;
        assert!(response.status_ok().unwrap());

        let changes = response.object_changes.unwrap();

        // 返回第一个（也是唯一一个）发布的包的ID
        let package_id = changes
            .iter()
            .find_map(|d| match d {
                ObjectChange::Published { package_id, .. } => Some(*package_id),
                _ => None,
            })
            .unwrap();

        // 找到升级能力ID
        let upgrade_cap = changes
            .iter()
            .find_map(|d| match d {
                ObjectChange::Created { object_id, .. } => Some(*object_id),
                _ => None,
            })
            .unwrap();

        // 将包ID添加到内部注册表
        add_package(package_id);

        (package_id, upgrade_cap)
    }

    /**
     * 升级已发布的包
     * 
     * 在测试链上升级指定的包，并返回新的包ID。
     * 
     * @param package_id - 要升级的包ID
     * @param upgrade_cap - 升级能力对象ID
     * @param module - 新模块的名称
     * @return 新的包ID
     */
    pub async fn upgrade(
        &mut self,
        package_id: ObjectID,
        upgrade_cap: ObjectID,
        module: &str,
    ) -> ObjectID {
        // 构建模块路径
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.extend(["..", "..", "example", module]);
        let compiled_package = BuildConfig::new_for_testing().build(&path).unwrap();

        // 准备升级
        let builder = self.cluster.sui_client().transaction_builder();

        let tx = builder
            .upgrade(
                self.cluster.get_address_0(),
                package_id,
                compiled_package.get_package_bytes(true),
                compiled_package.get_dependency_storage_package_ids(),
                upgrade_cap,
                UpgradePolicy::COMPATIBLE,
                compiled_package.get_package_digest(true).to_vec(),
                None,
                40_000_000_000,
            )
            .await
            .unwrap();
        let response = self.cluster.sign_and_execute_transaction(&tx).await;
        assert!(response.status_ok().unwrap());

        let changes = response.object_changes.unwrap();

        // 获取新发布的包ID
        let new_package_id = *changes
            .iter()
            .find_map(|d| match d {
                ObjectChange::Published { package_id, .. } => Some(package_id),
                _ => None,
            })
            .unwrap();

        // 更新内部注册表
        add_latest(package_id, new_package_id);

        new_package_id
    }

    /**
     * 注册密钥服务器
     * 
     * 在测试链上注册一个密钥服务器，并返回注册后的服务器对象ID。
     * 
     * @param package_id - Seal包ID
     * @param description - 服务器描述
     * @param url - 服务器URL
     * @param pk - 服务器的IBE公钥
     * @return 注册后的密钥服务器对象ID
     */
    pub async fn register_key_server(
        &mut self,
        package_id: ObjectID,
        description: &str,
        url: &str,
        pk: ibe::PublicKey,
    ) -> ObjectID {
        // 构建注册事务
        let tx = self
            .cluster
            .sui_client()
            .transaction_builder()
            .move_call(
                self.cluster.get_address_0(),
                package_id,
                "key_server",
                "register_and_transfer",
                vec![],
                vec![
                    SuiJsonValue::from_str(description).unwrap(),
                    SuiJsonValue::from_str(url).unwrap(), // 测试中不会使用的虚拟URL
                    SuiJsonValue::from_str(&0u8.to_string()).unwrap(), // 固定为BF-IBE算法
                    SuiJsonValue::new(json!(pk.to_byte_array().to_vec())).unwrap(),
                ],
                None,
                50_000_000,
                None,
            )
            .await
            .unwrap();
        let response = self.cluster.sign_and_execute_transaction(&tx).await;

        // 从响应中查找创建的KeyServer对象
        let service_objects = response
            .object_changes
            .unwrap()
            .into_iter()
            .filter_map(|d| match d {
                ObjectChange::Created {
                    object_type,
                    object_id,
                    ..
                } => Some((object_type.name, object_id)),
                _ => None,
            })
            .filter(|(name, _)| name.as_str() == "KeyServer")
            .collect::<Vec<_>>();
        assert_eq!(service_objects.len(), 1);
        service_objects[0].1
    }

    /**
     * 获取密钥服务器的公钥
     * 
     * 从链上获取指定密钥服务器对象的公钥列表。
     * 
     * @param object_ids - 密钥服务器对象ID列表
     * @return IBE公钥列表
     */
    pub async fn get_public_keys(&self, object_ids: &[ObjectID]) -> Vec<ibe::PublicKey> {
        // 获取对象数据
        let objects = self
            .cluster
            .sui_client()
            .read_api()
            .multi_get_object_with_options(
                object_ids.to_vec(),
                SuiObjectDataOptions::full_content(),
            )
            .await
            .unwrap();

        // 解析公钥字段
        objects
            .into_iter()
            .map(|o| {
                o.data
                    .unwrap()
                    .content
                    .unwrap()
                    .try_as_move()
                    .unwrap()
                    .fields
                    .field_value("pk")
                    .unwrap()
                    .to_json_value()
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect::<Vec<_>>()
            })
            .map(|v| ibe::PublicKey::from_byte_array(&v.try_into().unwrap()).unwrap())
            .collect()
    }
}

/**
 * 测试包升级功能
 * 
 * 此测试验证SealTestCluster能够正确升级Move包，并返回新的包ID。
 */
#[tokio::test]
async fn test_pkg_upgrade() {
    // 创建测试集群
    let mut setup = SealTestCluster::new(1, 1).await;
    
    // 发布模式合约
    let (package_id, upgrade_cap) = setup.publish("patterns").await;
    
    // 升级包（实际上是相同内容）
    let new_package_id = setup.upgrade(package_id, upgrade_cap, "patterns").await;
    
    // 验证新旧包ID不同
    assert_ne!(package_id, new_package_id);
}
