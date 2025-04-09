// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 密钥服务器实现
 * 
 * 此模块实现了Seal密钥服务器的核心功能，包括：
 * 1. HTTP API端点，用于处理密钥请求
 * 2. 用户请求验证机制
 * 3. 使用IBE为授权用户提供解密密钥
 * 4. 安全策略验证
 */

use crate::externals::{current_epoch_time, duration_since, get_reference_gas_price};
use crate::metrics::{call_with_duration, observation_callback, status_callback, Metrics};
use crate::signed_message::{signed_message, signed_request};
use crate::types::MasterKeyPOP;
use anyhow::Result;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{extract::State, Json};
use core::time::Duration;
use crypto::elgamal::encrypt;
use crypto::ibe;
use crypto::ibe::create_proof_of_possession;
use errors::InternalError;
use externals::get_latest_checkpoint_timestamp;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::VerifyingKey;
use mysten_service::get_mysten_service;
use mysten_service::metrics::start_basic_prometheus_server;
use mysten_service::package_name;
use mysten_service::package_version;
use mysten_service::serve;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;
use sui_sdk::error::SuiRpcResult;
use sui_sdk::rpc_types::SuiTransactionBlockEffectsAPI;
use sui_sdk::types::base_types::{ObjectID, SuiAddress};
use sui_sdk::types::signature::GenericSignature;
use sui_sdk::types::transaction::{ProgrammableTransaction, TransactionKind};
use sui_sdk::verify_personal_message_signature::verify_personal_message_signature;
use sui_sdk::{SuiClient, SuiClientBuilder};
use tap::tap::TapFallible;
use tokio::sync::watch::{channel, Receiver};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};
use types::{ElGamalPublicKey, ElgamalEncryption, ElgamalVerificationKey, IbeMasterKey, Network};
use valid_ptb::ValidPtb;

// 内部模块
mod cache;        // 缓存系统，优化性能
mod errors;       // 错误类型定义
mod externals;    // 外部接口，如时间和gas价格
mod signed_message; // 签名消息处理
mod types;        // 数据类型定义
mod valid_ptb;    // 可编程交易块验证

mod metrics;      // 性能指标收集
#[cfg(test)]
pub mod tests;    // 测试模块

/// 允许的全节点数据过时时间
/// 设置此持续时间时，注意Sui上的时间戳可能比当前时间稍晚，但不应超过一秒。
const ALLOWED_STALENESS: Duration = Duration::from_secs(120);

/// 更新最新检查点时间戳的间隔
const CHECKPOINT_UPDATE_INTERVAL: Duration = Duration::from_secs(10);

/// 更新参考gas价格的间隔
const RGP_UPDATE_INTERVAL: Duration = Duration::from_secs(60);

/// 会话密钥的最大生存时间（分钟）
const SESSION_KEY_TTL_MAX: u16 = 10;

/// 最大预算的1%
const GAS_BUDGET: u64 = 500_000_000;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/**
 * 会话证书，由用户签名
 * 用于验证用户身份和请求合法性
 * 
 * 包含以下信息：
 * - 用户地址
 * - 会话验证密钥
 * - 创建时间
 * - 生存时间
 * - 用户签名
 */
#[derive(Clone, Serialize, Deserialize, Debug)]
struct Certificate {
    pub user: SuiAddress,           // 用户的Sui地址
    pub session_vk: Ed25519PublicKey, // 会话验证密钥
    pub creation_time: u64,         // 创建时间（Unix时间戳）
    pub ttl_min: u16,               // 生存时间（分钟）
    pub signature: GenericSignature, // 用户签名
}

/**
 * 获取密钥请求结构
 * 
 * 客户端发送此请求以获取解密密钥
 * 包含签名的请求数据和验证信息
 */
#[derive(Serialize, Deserialize)]
struct FetchKeyRequest {
    // 以下字段必须签名，以防止他人代表用户发送请求并能够获取密钥
    ptb: String, // 必须遵循特定结构，参见ValidPtb
    // 我们不想仅依靠HTTPS来限制对此用户的响应，因为在多个服务的情况下，
    // 一个服务可以对另一个服务进行重放攻击以获取其他服务的密钥。
    enc_key: ElGamalPublicKey,          // ElGamal加密公钥
    enc_verification_key: ElgamalVerificationKey, // ElGamal验证密钥
    request_signature: Ed25519Signature, // 请求签名
    
    certificate: Certificate,          // 用户会话证书
}

/// 密钥ID类型（字节数组）
type KeyId = Vec<u8>;

/// 时间戳类型（64位无符号整数）
type Timestamp = u64;

/**
 * 解密密钥结构
 * 
 * 包含密钥ID和加密后的密钥
 * 返回给客户端用于解密其数据
 */
#[derive(Serialize, Deserialize)]
struct DecryptionKey {
    id: KeyId,                      // 密钥标识符
    encrypted_key: ElgamalEncryption, // 加密的密钥
}

/**
 * 获取密钥响应结构
 * 
 * 服务器返回的加密密钥列表
 */
#[derive(Serialize, Deserialize)]
struct FetchKeyResponse {
    decryption_keys: Vec<DecryptionKey>, // 解密密钥列表
}

/**
 * 服务器状态结构
 * 
 * 包含服务器运行所需的核心组件和配置
 */
#[derive(Clone)]
struct Server {
    sui_client: SuiClient,              // Sui客户端
    network: Network,                   // 网络配置
    master_key: IbeMasterKey,           // IBE主密钥
    key_server_object_id: ObjectID,     // 密钥服务器对象ID
    key_server_object_id_sig: MasterKeyPOP, // 主密钥持有证明
}

impl Server {
    /**
     * 创建新的服务器实例
     * 
     * 初始化服务器状态，包括连接到Sui网络并创建密钥持有证明
     * 
     * 参数:
     * @param master_key - IBE主密钥
     * @param network - 网络配置
     * @param key_server_object_id - 服务器对象ID
     * 
     * 返回:
     * 服务器实例
     */
    async fn new(
        master_key: IbeMasterKey,
        network: Network,
        key_server_object_id: ObjectID,
    ) -> Self {
        let sui_client = SuiClientBuilder::default()
            .build(&network.node_url())
            .await
            .expect("SuiClientBuilder should not failed unless provided with invalid network url");
        info!(
            "Server started with public key: {:?} and network: {:?}",
            Base64::encode(
                bcs::to_bytes(&ibe::public_key_from_master_key(&master_key)).expect("valid pk")
            ),
            network
        );

        let key_server_object_id_sig =
            create_proof_of_possession(&master_key, &key_server_object_id.into_bytes());

        Server {
            sui_client,
            network,
            master_key,
            key_server_object_id,
            key_server_object_id_sig,
        }
    }

    /**
     * 检查请求签名的有效性
     * 
     * 验证用户证书和会话签名，确保请求的合法性
     * 
     * 参数:
     * @param pkg_id - 包ID
     * @param ptb - 可编程交易块
     * @param enc_key - ElGamal加密公钥
     * @param enc_verification_key - ElGamal验证密钥
     * @param session_sig - 会话签名
     * @param cert - 用户证书
     * @param req_id - 请求ID（用于日志）
     * 
     * 返回:
     * 成功时返回Ok(())，失败时返回错误
     */
    #[allow(clippy::too_many_arguments)]
    async fn check_signature(
        &self,
        pkg_id: &ObjectID,
        ptb: &ProgrammableTransaction,
        enc_key: &ElGamalPublicKey,
        enc_verification_key: &ElgamalVerificationKey,
        session_sig: &Ed25519Signature,
        cert: &Certificate,
        req_id: Option<&str>,
    ) -> Result<(), InternalError> {
        // 检查证书有效性
        if cert.ttl_min > SESSION_KEY_TTL_MAX
            || cert.creation_time > current_epoch_time()
            || current_epoch_time() < 60_000 * (cert.ttl_min as u64) // 检查溢出
            || current_epoch_time() - 60_000 * (cert.ttl_min as u64) > cert.creation_time
        {
            debug!(
                "Certificate has invalid expiration time (req_id: {:?})",
                req_id
            );
            return Err(InternalError::InvalidCertificate);
        }

        let msg = signed_message(pkg_id, &cert.session_vk, cert.creation_time, cert.ttl_min);
        debug!(
            "Checking signature on message: {:?} (req_id: {:?})",
            msg, req_id
        );
        // 验证用户签名
        verify_personal_message_signature(
            cert.signature.clone(),
            msg.as_bytes(),
            cert.user,
            Some(self.sui_client.clone()),
        )
        .await
        .tap_err(|e| {
            debug!(
                "Signature verification failed: {:?} (req_id: {:?})",
                e, req_id
            );
        })
        .map_err(|_| InternalError::InvalidSignature)?;

        // 验证会话签名（请求签名）
        let signed_msg = signed_request(ptb, enc_key, enc_verification_key);
        cert.session_vk
            .verify(&signed_msg, session_sig)
            .map_err(|_| {
                debug!(
                    "Session signature verification failed (req_id: {:?})",
                    req_id
                );
                InternalError::InvalidSessionSignature
            })
    }

    /**
     * 检查策略合规性
     * 
     * 通过模拟执行交易确认用户是否有权限获取密钥
     * 
     * 参数:
     * @param sender - 发送者地址
     * @param vptb - 验证过的可编程交易块
     * @param gas_price - 当前gas价格
     * @param req_id - 请求ID（用于日志）
     * 
     * 返回:
     * 成功时返回Ok(())，失败时返回错误
     */
    async fn check_policy(
        &self,
        sender: SuiAddress,
        vptb: &ValidPtb,
        gas_price: u64,
        req_id: Option<&str>,
    ) -> Result<(), InternalError> {
        debug!(
            "Checking policy for ptb: {:?} (req_id: {:?})",
            vptb.ptb(),
            req_id
        );
        // 评估`seal_approve*`函数
        let tx_data = self
            .sui_client
            .transaction_builder()
            .tx_data_for_dry_run(
                sender,
                TransactionKind::ProgrammableTransaction(vptb.ptb().clone()),
                GAS_BUDGET,
                gas_price,
                None,
                None,
            )
            .await;
        let dry_run_res = self
            .sui_client
            .read_api()
            .dry_run_transaction_block(tx_data)
            .await
            .map_err(|e| {
                warn!("Dry run execution failed ({:?}) (req_id: {:?})", e, req_id);
                InternalError::Failure
            })?;
        debug!("Dry run response: {:?} (req_id: {:?})", dry_run_res, req_id);
        if dry_run_res.effects.status().is_err() {
            debug!("Dry run execution asserted (req_id: {:?})", req_id);
            // TODO: 我们是否应该根据状态返回不同的错误，例如InsufficientGas？
            return Err(InternalError::NoAccess);
        }

        // 一切正常！
        Ok(())
    }

    /**
     * 检查请求的有效性
     * 
     * 全面验证请求，包括：
     * 1. 验证PTB格式
     * 2. 验证签名
     * 3. 检查策略合规性
     * 
     * 参数:
     * @param ptb_str - PTB的Base64编码字符串
     * @param enc_key - ElGamal加密公钥
     * @param enc_verification_key - ElGamal验证密钥 
     * @param request_signature - 请求签名
     * @param certificate - 用户证书
     * @param gas_price - 当前gas价格
     * @param metrics - 性能指标收集器
     * @param req_id - 请求ID（用于日志）
     * 
     * 返回:
     * 成功时返回密钥ID列表，失败时返回错误
     */
    #[allow(clippy::too_many_arguments)]
    async fn check_request(
        &self,
        ptb_str: &str,
        enc_key: &ElGamalPublicKey,
        enc_verification_key: &ElgamalVerificationKey,
        request_signature: &Ed25519Signature,
        certificate: &Certificate,
        gas_price: u64,
        metrics: Option<&Metrics>,
        req_id: Option<&str>,
    ) -> Result<Vec<KeyId>, InternalError> {
        debug!(
            "Checking request for ptb_str: {:?}, cert {:?} (req_id: {:?})",
            ptb_str, certificate, req_id
        );
        let ptb_b64 = Base64::decode(ptb_str).map_err(|_| InternalError::InvalidPTB)?;
        let ptb: ProgrammableTransaction =
            bcs::from_bytes(&ptb_b64).map_err(|_| InternalError::InvalidPTB)?;
        let valid_ptb = ValidPtb::try_from(ptb.clone())?;

        // 向指标报告请求中的ID数量
        if let Some(m) = metrics {
            m.requests_per_number_of_ids
                .observe(valid_ptb.inner_ids().len() as f64);
        }

        // 处理包升级：只调用最新版本，但使用第一个版本作为命名空间
        let (first_pkg_id, last_pkg_id) =
            call_with_duration(metrics.map(|m| &m.fetch_pkg_ids_duration), || async {
                externals::fetch_first_and_last_pkg_id(&valid_ptb.pkg_id(), &self.network).await
            })
            .await?;

        if valid_ptb.pkg_id() != last_pkg_id {
            debug!(
                "Last package version is {:?} while ptb uses {:?} (req_id: {:?})",
                last_pkg_id,
                valid_ptb.pkg_id(),
                req_id
            );
            return Err(InternalError::OldPackageVersion);
        }

        // 检查所有条件
        self.check_signature(
            &first_pkg_id,
            &ptb,
            enc_key,
            enc_verification_key,
            request_signature,
            certificate,
            req_id,
        )
        .await?;

        call_with_duration(metrics.map(|m| &m.check_policy_duration), || async {
            self.check_policy(certificate.user, &valid_ptb, gas_price, req_id)
                .await
        })
        .await?;

        info!(
            "Valid request: {}",
            json!({ "user": certificate.user, "package_id": valid_ptb.pkg_id(), "req_id": req_id })
        );

        // 返回以第一个包ID为前缀的完整ID
        Ok(valid_ptb.full_ids(&first_pkg_id))
    }

    /**
     * 创建响应
     * 
     * 为每个密钥ID生成加密的解密密钥
     * 
     * 参数:
     * @param ids - 密钥ID列表
     * @param enc_key - 用于加密的ElGamal公钥
     * 
     * 返回:
     * 包含加密密钥的响应
     */
    fn create_response(&self, ids: &[KeyId], enc_key: &ElGamalPublicKey) -> FetchKeyResponse {
        debug!("Checking response for ids: {:?}", ids);
        let decryption_keys = ids
            .iter()
            .map(|id| {
                // 请求的密钥
                let key = ibe::extract(&self.master_key, id);
                // 使用用户的公钥对密钥进行ElGamal加密
                let encrypted_key = encrypt(&mut thread_rng(), &key, enc_key);
                DecryptionKey {
                    id: id.to_owned(),
                    encrypted_key,
                }
            })
            .collect();
        FetchKeyResponse { decryption_keys }
    }

    /**
     * 生成定期更新器
     * 
     * 启动一个线程，定期获取值并将其发送到接收器
     * 用于维护服务器状态，如最新检查点时间和gas价格
     * 
     * 参数:
     * @param update_interval - 更新间隔
     * @param fetch_fn - 获取值的函数
     * @param value_name - 值名称（用于日志）
     * @param subscriber - 值更新时的回调
     * @param duration_callback - 持续时间回调
     * @param success_callback - 成功回调
     * 
     * 返回:
     * 包含更新值的接收器
     */
    async fn spawn_periodic_updater<F, Fut, G, H, I>(
        &self,
        update_interval: Duration,
        fetch_fn: F,
        value_name: &'static str,
        subscriber: Option<G>,
        duration_callback: Option<H>,
        success_callback: Option<I>,
    ) -> Receiver<u64>
    where
        F: Fn(SuiClient) -> Fut + Send + 'static,
        Fut: Future<Output = SuiRpcResult<u64>> + Send,
        G: Fn(u64) + Send + 'static,
        H: Fn(Duration) + Send + 'static,
        I: Fn(bool) + Send + 'static,
    {
        let (sender, mut receiver) = channel(0);
        let local_client = self.sui_client.clone();
        let mut interval = tokio::time::interval(update_interval);

        // 如果由于全节点响应缓慢而错过了一个tick，我们不需要
        // 赶上来，而是延迟下一个tick。
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        tokio::task::spawn(async move {
            loop {
                let now = Instant::now();
                let result = fetch_fn(local_client.clone()).await;
                if let Some(dcb) = &duration_callback {
                    dcb(now.elapsed());
                }
                if let Some(scb) = &success_callback {
                    scb(result.is_ok());
                }
                match result {
                    Ok(new_value) => {
                        sender
                            .send(new_value)
                            .expect("Channel closed, this should never happen");
                        debug!("{} updated to: {:?}", value_name, new_value);
                        if let Some(subscriber) = &subscriber {
                            subscriber(new_value);
                        }
                    }
                    Err(e) => warn!("Failed to get {}: {:?}", value_name, e),
                }
                interval.tick().await;
            }
        });

        // 这会阻塞直到获取到一个值。
        // 这样做是为了确保服务器在启动后立即可以处理请求。
        // 如果这不可能，我们无法更新值，服务器不应该启动。
        receiver
            .changed()
            .await
            .unwrap_or_else(|_| panic!("Failed to get {}", value_name));
        receiver
    }

    /**
     * 生成最新检查点时间戳更新器
     * 
     * 定期获取最新的检查点时间戳，用于确保服务器使用最新数据
     * 
     * 参数:
     * @param update_interval - 更新间隔
     * @param metrics - 性能指标收集器
     * 
     * 返回:
     * 包含检查点时间戳的接收器
     */
    async fn spawn_latest_checkpoint_timestamp_updater(
        &self,
        update_interval: Duration,
        metrics: Option<&Metrics>,
    ) -> Receiver<Timestamp> {
        self.spawn_periodic_updater(
            update_interval,
            get_latest_checkpoint_timestamp,
            "latest checkpoint timestamp",
            metrics.map(|m| {
                observation_callback(&m.checkpoint_timestamp_delay, |ts| {
                    duration_since(ts) as f64
                })
            }),
            metrics.map(|m| {
                observation_callback(&m.get_checkpoint_timestamp_duration, |d: Duration| {
                    d.as_millis() as f64
                })
            }),
            metrics.map(|m| status_callback(&m.get_checkpoint_timestamp_status)),
        )
        .await
    }

    /**
     * 生成参考gas价格更新器
     * 
     * 定期获取当前的参考gas价格，用于交易模拟
     * 
     * 参数:
     * @param update_interval - 更新间隔
     * @param metrics - 性能指标收集器
     * 
     * 返回:
     * 包含gas价格的接收器
     */
    async fn spawn_reference_gas_price_updater(
        &self,
        update_interval: Duration,
        metrics: Option<&Metrics>,
    ) -> Receiver<u64> {
        self.spawn_periodic_updater(
            update_interval,
            get_reference_gas_price,
            "RGP",
            None::<fn(u64)>,
            None::<fn(Duration)>,
            metrics.map(|m| status_callback(&m.get_reference_gas_price_status)),
        )
        .await
    }
}

/**
 * 处理获取密钥请求
 * 
 * 处理客户端的密钥请求，验证其有效性并返回加密的密钥
 * 
 * 参数:
 * @param app_state - 应用状态
 * @param headers - HTTP请求头
 * @param payload - 请求负载
 * 
 * 返回:
 * 成功时返回密钥响应，失败时返回错误
 */
async fn handle_fetch_key(
    State(app_state): State<MyState>,
    headers: HeaderMap,
    Json(payload): Json<FetchKeyRequest>,
) -> Result<Json<FetchKeyResponse>, InternalError> {
    let req_id = headers
        .get("Request-Id")
        .map(|v| v.to_str().unwrap_or_default());
    let version = headers.get("Client-Sdk-Version");
    let sdk_type = headers.get("Client-Sdk-Type");
    let target_api_version = headers.get("Client-Target-Api-Version");
    info!(
        "Request id: {:?}, SDK version: {:?}, SDK type: {:?}, Target API version: {:?}",
        req_id, version, sdk_type, target_api_version
    );

    app_state.metrics.requests.inc();
    app_state.check_full_node_is_fresh(ALLOWED_STALENESS)?;

    app_state
        .server
        .check_request(
            &payload.ptb,
            &payload.enc_key,
            &payload.enc_verification_key,
            &payload.request_signature,
            &payload.certificate,
            app_state.reference_gas_price(),
            Some(&app_state.metrics),
            req_id,
        )
        .await
        .map(|full_id| Json(app_state.server.create_response(&full_id, &payload.enc_key)))
        .tap_err(|e| app_state.metrics.observe_error(e.as_str()))
}

/**
 * 获取服务信息响应
 * 
 * 包含服务ID和主密钥持有证明
 */
#[derive(Serialize, Deserialize)]
struct GetServiceResponse {
    service_id: ObjectID,
    pop: MasterKeyPOP,
}

/**
 * 处理获取服务信息请求
 * 
 * 返回服务器ID和密钥持有证明，用于客户端验证服务器身份
 * 
 * 参数:
 * @param app_state - 应用状态
 * 
 * 返回:
 * 服务信息响应
 */
async fn handle_get_service(
    State(app_state): State<MyState>,
) -> Result<Json<GetServiceResponse>, InternalError> {
    app_state.metrics.service_requests.inc();
    Ok(Json(GetServiceResponse {
        service_id: app_state.server.key_server_object_id,
        pop: app_state.server.key_server_object_id_sig,
    }))
}

/**
 * 应用状态
 * 
 * 包含共享的服务器状态，用于处理HTTP请求
 */
#[derive(Clone)]
struct MyState {
    metrics: Arc<Metrics>,
    server: Arc<Server>,
    latest_checkpoint_timestamp_receiver: Receiver<Timestamp>,
    reference_gas_price: Receiver<u64>,
}

impl MyState {
    /**
     * 检查全节点数据是否新鲜
     * 
     * 验证最新检查点时间戳是否在允许的过时时间范围内
     * 
     * 参数:
     * @param allowed_staleness - 允许的过时时间
     * 
     * 返回:
     * 成功时返回Ok(())，如果数据过时则返回错误
     */
    fn check_full_node_is_fresh(&self, allowed_staleness: Duration) -> Result<(), InternalError> {
        let staleness = duration_since(*self.latest_checkpoint_timestamp_receiver.borrow());
        if staleness > allowed_staleness.as_millis() as i64 {
            warn!(
                "Full node is stale. Latest checkpoint is {} ms old.",
                staleness
            );
            return Err(InternalError::Failure);
        }
        Ok(())
    }

    /**
     * 获取当前参考gas价格
     * 
     * 返回:
     * 当前gas价格
     */
    fn reference_gas_price(&self) -> u64 {
        *self.reference_gas_price.borrow()
    }
}

/**
 * 主函数
 * 
 * 初始化并启动密钥服务器
 * 
 * 返回:
 * 操作结果
 */
#[tokio::main]
async fn main() -> Result<()> {
    let master_key = env::var("MASTER_KEY").expect("MASTER_KEY must be set");
    let object_id = env::var("KEY_SERVER_OBJECT_ID").expect("KEY_SERVER_OBJECT_ID must be set");
    let network = env::var("NETWORK")
        .map(|n| Network::from_str(&n))
        .unwrap_or(Network::Testnet);

    let _guard = mysten_service::logging::init();
    info!("Logging set up, setting up metrics");

    // 初始化指标
    let registry = start_basic_prometheus_server();
    // 连接自定义应用指标
    let metrics = Arc::new(Metrics::new(&registry));
    info!("Metrics set up, starting service");

    info!("Starting server, version {}", PACKAGE_VERSION);

    let s = Server::new(
        IbeMasterKey::from_byte_array(
            &Base64::decode(&master_key)
                .expect("MASTER_KEY should be base64 encoded")
                .try_into()
                .expect("Invalid MASTER_KEY length"),
        )
        .expect("Invalid MASTER_KEY value"),
        network,
        ObjectID::from_hex_literal(&object_id).expect("Invalid KEY_SERVER_OBJECT_ID"),
    )
    .await;
    let server = Arc::new(s);

    // 启动更新服务器状态的任务
    let latest_checkpoint_timestamp_receiver = server
        .spawn_latest_checkpoint_timestamp_updater(CHECKPOINT_UPDATE_INTERVAL, Some(&metrics))
        .await;
    let reference_gas_price = server
        .spawn_reference_gas_price_updater(RGP_UPDATE_INTERVAL, Some(&metrics))
        .await;

    let state = MyState {
        metrics,
        server,
        latest_checkpoint_timestamp_receiver,
        reference_gas_price,
    };

    // 配置CORS
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);

    // 配置HTTP路由
    let app = get_mysten_service(package_name!(), package_version!())
        .route("/v1/fetch_key", post(handle_fetch_key))
        .route("/v1/service", get(handle_get_service))
        .with_state(state)
        .layer(cors);

    // 启动服务器
    serve(app).await
}
