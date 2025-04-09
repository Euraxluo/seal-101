// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 外部接口交互模块
 * 
 * 本模块负责密钥服务器与外部系统的交互，提供以下功能：
 * 1. 获取包ID信息 - 从GraphQL接口获取最新和初始包ID信息
 * 2. 区块链状态查询 - 获取最新的区块链检查点和gasPrice
 * 3. 时间相关工具函数 - 计算时间差和获取当前时间
 * 4. 缓存管理 - 使用LRU缓存优化外部调用性能
 * 
 * 这些功能保证了服务器可以高效地验证请求并访问最新的区块链数据。
 */

use crate::cache::{Cache, CACHE_SIZE, CACHE_TTL};
use crate::errors::InternalError;
use crate::types::Network;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde_json::Value;
use std::str::FromStr;
use sui_sdk::error::SuiRpcResult;
use sui_sdk::rpc_types::CheckpointId;
use sui_sdk::SuiClient;
use sui_types::base_types::ObjectID;
use tap::TapFallible;
use tracing::{debug, warn};

/**
 * 包ID缓存
 * 
 * 使用全局静态Lazy初始化的LRU缓存
 * 存储格式：(ObjectID, (首个版本ID, 最新版本ID))
 * 用于避免重复查询GraphQL API获取包版本信息
 */
static CACHE: Lazy<Cache<ObjectID, (ObjectID, ObjectID)>> =
    Lazy::new(|| Cache::new(CACHE_TTL, CACHE_SIZE));

/**
 * 添加最新包ID到缓存 (仅用于测试)
 * 
 * 更新缓存中指定包ID的最新版本
 * 同时更新原始最新版本和新最新版本的映射
 * 
 * 参数:
 * @param pkg_id - 包ID
 * @param latest - 最新版本的包ID
 */
#[cfg(test)]
pub(crate) fn add_latest(pkg_id: ObjectID, latest: ObjectID) {
    match CACHE.get(&pkg_id) {
        Some((first, old_latest)) => {
            CACHE.insert(pkg_id, (first, latest));
            CACHE.insert(latest, (first, latest));
            CACHE.insert(old_latest, (first, latest));
        }
        None => panic!("Package is not in cache"),
    }
}

/**
 * 添加包ID到缓存 (仅用于测试)
 * 
 * 向缓存中添加新的包ID，假设首个版本和最新版本相同
 * 
 * 参数:
 * @param pkg_id - 包ID
 */
#[cfg(test)]
pub(crate) fn add_package(pkg_id: ObjectID) {
    CACHE.insert(pkg_id, (pkg_id, pkg_id));
}

/**
 * 获取包的首个和最新版本ID
 * 
 * 首先尝试从缓存获取，如果缓存未命中，则从GraphQL API获取
 * 获取成功后同时更新缓存以备将来使用
 * 
 * 参数:
 * @param pkg_id - 要查询的包ID
 * @param network - 网络配置信息
 * 
 * 返回:
 * 成功时返回(首个版本ID, 最新版本ID)元组，失败时返回错误
 */
pub(crate) async fn fetch_first_and_last_pkg_id(
    pkg_id: &ObjectID,
    network: &Network,
) -> Result<(ObjectID, ObjectID), InternalError> {
    match CACHE.get(pkg_id) {
        Some((first, latest)) => Ok((first, latest)),
        None => {
            let graphql_client = Client::new();
            let url = network.graphql_url();
            let query = serde_json::json!({
                "query": format!(
                    r#"
                    query {{
                        latestPackage(
                            address: "{}"
                        ) {{
                            address
                            packageAtVersion(version: 1) {{
                                address
                            }}
                        }}
                    }}
                    "#,
                    pkg_id
                )
            });
            let response = graphql_client.post(url).json(&query).send().await;
            debug!("Graphql response: {:?}", response);
            let response = response
                .map_err(|_| InternalError::Failure)?
                .json::<Value>()
                .await
                .map_err(|_| InternalError::Failure)?;

            let first = response["data"]["latestPackage"]["packageAtVersion"]["address"]
                .as_str()
                .ok_or(InternalError::InvalidPackage)?
                .to_string();
            let latest = response["data"]["latestPackage"]["address"]
                .as_str()
                .ok_or(InternalError::InvalidPackage)?
                .to_string();
            let (first, latest) = (
                ObjectID::from_str(&first).map_err(|_| InternalError::Failure)?,
                ObjectID::from_str(&latest).map_err(|_| InternalError::Failure)?,
            );
            CACHE.insert(*pkg_id, (first, latest));
            Ok((first, latest))
        }
    }
}

/**
 * 获取最新检查点的时间戳
 * 
 * 从Sui区块链获取最新检查点的时间戳信息
 * 这对于验证请求的新鲜度至关重要
 * 
 * 参数:
 * @param client - Sui客户端实例
 * 
 * 返回:
 * 最新检查点的时间戳(毫秒)
 */
pub(crate) async fn get_latest_checkpoint_timestamp(client: SuiClient) -> SuiRpcResult<u64> {
    let latest_checkpoint_sequence_number = client
        .read_api()
        .get_latest_checkpoint_sequence_number()
        .await?;
    let checkpoint = client
        .read_api()
        .get_checkpoint(CheckpointId::SequenceNumber(
            latest_checkpoint_sequence_number,
        ))
        .await?;
    Ok(checkpoint.timestamp_ms)
}

/**
 * 获取参考Gas价格
 * 
 * 从Sui区块链获取当前的参考Gas价格
 * 用于验证交易Gas价格是否合理
 * 
 * 参数:
 * @param client - Sui客户端实例
 * 
 * 返回:
 * 当前参考Gas价格
 */
pub(crate) async fn get_reference_gas_price(client: SuiClient) -> SuiRpcResult<u64> {
    let rgp = client
        .read_api()
        .get_reference_gas_price()
        .await
        .tap_err(|e| {
            warn!("Failed retrieving RGP ({:?})", e);
        })?;
    Ok(rgp)
}

/**
 * 计算时间差
 * 
 * 计算当前时间与给定偏移时间之间的差距(毫秒)
 * 用于验证请求的时效性
 * 
 * 参数:
 * @param offset - 偏移时间(毫秒时间戳)
 * 
 * 返回:
 * 当前时间与偏移时间的差值(毫秒)，转换为i64
 * 调用者需注意可能的溢出风险
 */
pub(crate) fn duration_since(offset: u64) -> i64 {
    let now = current_epoch_time() as i64;
    now - offset as i64
}

/**
 * 获取当前时间
 * 
 * 返回当前的UNIX纪元时间(毫秒)
 * 用于时间戳比较和请求有效性验证
 * 
 * 返回:
 * 当前UNIX时间戳(毫秒)
 */
pub(crate) fn current_epoch_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("fixed start time")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use crate::externals::fetch_first_and_last_pkg_id;
    use crate::types::Network;
    use crate::InternalError;
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::secp256k1::Secp256k1KeyPair;
    use fastcrypto::secp256r1::Secp256r1KeyPair;
    use shared_crypto::intent::{Intent, IntentMessage, PersonalMessage};
    use std::str::FromStr;
    use sui_sdk::types::crypto::{get_key_pair, Signature};
    use sui_sdk::types::signature::GenericSignature;
    use sui_sdk::verify_personal_message_signature::verify_personal_message_signature;
    use sui_types::base_types::ObjectID;

    /**
     * 测试获取包的首个和最新版本ID
     * 
     * 验证从主网获取包版本信息的功能
     */
    #[tokio::test]
    async fn test_fetch_first_and_last_pkg_id() {
        let address = ObjectID::from_str(
            "0xd92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5",
        )
        .unwrap();

        match fetch_first_and_last_pkg_id(&address, &Network::Mainnet).await {
            Ok((first, latest)) => {
                assert!(!first.is_empty(), "First address should not be empty");
                assert!(!latest.is_empty(), "Latest address should not be empty");
                println!("First address: {:?}", first);
                println!("Latest address: {:?}", latest);
            }
            Err(e) => panic!("Test failed with error: {:?}", e),
        }
    }

    /**
     * 测试使用无效包ID
     * 
     * 验证当提供无效的包ID时，函数应返回适当的错误
     */
    #[tokio::test]
    async fn test_fetch_first_and_last_pkg_id_with_invalid_id() {
        let invalid_address = ObjectID::ZERO;
        let result = fetch_first_and_last_pkg_id(&invalid_address, &Network::Mainnet).await;
        assert!(matches!(result, Err(InternalError::InvalidPackage)));
    }

    /**
     * 测试使用无效的GraphQL URL
     * 
     * 验证当GraphQL服务不可用时，函数应返回适当的错误
     */
    #[tokio::test]
    async fn test_fetch_first_and_last_pkg_id_with_invalid_graphql_url() {
        let address = ObjectID::from_str(
            "0xd92bc457b42d48924087ea3f22d35fd2fe9afdf5bdfe38cc51c0f14f3282f6d5",
        )
        .unwrap();

        // 使用自定义网络配置，带有无效URL以模拟获取失败
        let invalid_network = Network::Custom {
            graphql_url: "http://invalid-url".to_string(),
            node_url: "http://invalid-url".to_string(),
        };

        let result = fetch_first_and_last_pkg_id(&address, &invalid_network).await;
        assert!(matches!(result, Err(InternalError::Failure)));
    }

    /**
     * 测试简单签名验证
     * 
     * 验证不同类型的签名验证功能是否正常工作
     * 包括Ed25519、Secp256k1和Secp256r1签名
     */
    #[tokio::test]
    async fn test_simple_sigs() {
        let personal_msg = PersonalMessage {
            message: "hello".as_bytes().to_vec(),
        };
        let msg_with_intent = IntentMessage::new(Intent::personal_message(), personal_msg.clone());

        // 测试Ed25519签名
        {
            let (addr, sk): (_, Ed25519KeyPair) = get_key_pair();
            let sig = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, &sk));
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                addr,
                None
            )
            .await
            .is_ok());

            let (wrong_addr, _): (_, Ed25519KeyPair) = get_key_pair();
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                wrong_addr,
                None
            )
            .await
            .is_err());

            let wrong_msg = PersonalMessage {
                message: "wrong".as_bytes().to_vec(),
            };
            assert!(
                verify_personal_message_signature(sig.clone(), &wrong_msg.message, addr, None)
                    .await
                    .is_err()
            );
        }
        
        // 测试Secp256k1签名
        {
            let (addr, sk): (_, Secp256k1KeyPair) = get_key_pair();
            let sig = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, &sk));
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                addr,
                None
            )
            .await
            .is_ok());
            let (wrong_addr, _): (_, Secp256k1KeyPair) = get_key_pair();
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                wrong_addr,
                None
            )
            .await
            .is_err());
            let wrong_msg = PersonalMessage {
                message: "wrong".as_bytes().to_vec(),
            };
            assert!(
                verify_personal_message_signature(sig.clone(), &wrong_msg.message, addr, None)
                    .await
                    .is_err()
            );
        }
        
        // 测试Secp256r1签名
        {
            let (addr, sk): (_, Secp256r1KeyPair) = get_key_pair();
            let sig = GenericSignature::Signature(Signature::new_secure(&msg_with_intent, &sk));
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                addr,
                None
            )
            .await
            .is_ok());

            let (wrong_addr, _): (_, Secp256r1KeyPair) = get_key_pair();
            assert!(verify_personal_message_signature(
                sig.clone(),
                &personal_msg.message,
                wrong_addr,
                None
            )
            .await
            .is_err());
            let wrong_msg = PersonalMessage {
                message: "wrong".as_bytes().to_vec(),
            };
            assert!(
                verify_personal_message_signature(sig.clone(), &wrong_msg.message, addr, None)
                    .await
                    .is_err()
            );
        }
    }
}
