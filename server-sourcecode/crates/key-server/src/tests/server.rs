// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 密钥服务器后台更新机制测试模块
 * 
 * 本模块测试密钥服务器的各种后台更新机制的功能，包括:
 * 1. 检查点时间戳获取和更新功能
 * 2. 参考燃气价格(reference gas price)更新功能
 * 这些更新机制对于服务器正常运行和安全性非常重要。
 */

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_test::traced_test;

use crate::externals::get_latest_checkpoint_timestamp;
use crate::tests::SealTestCluster;

/**
 * 测试获取最新检查点时间戳功能
 * 
 * 此测试验证服务器能够正确获取Sui网络上最新检查点的时间戳，
 * 并确保此时间戳与当前系统时间在合理的误差范围内。
 */
#[tokio::test]
async fn test_get_latest_checkpoint_timestamp() {
    // 创建测试集群，不需要密钥服务器和用户
    let tc = SealTestCluster::new(0, 0).await;

    // 设置可接受的时间误差（毫秒）
    let tolerance = 20000;
    
    // 从网络获取最新检查点时间戳
    let timestamp: u64 = get_latest_checkpoint_timestamp(tc.cluster.sui_client().clone())
        .await
        .unwrap();

    // 获取当前系统时间
    let actual_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    // 验证网络时间戳与系统时间的差异在容许范围内
    let diff = actual_timestamp - timestamp;
    assert!(diff < tolerance);
}

/**
 * 测试时间戳后台更新功能
 * 
 * 此测试验证服务器能够按照指定的时间间隔自动更新检查点时间戳，
 * 并且更新后的时间戳始终保持在增长。这对于防止重放攻击非常重要。
 */
#[tokio::test]
async fn test_timestamp_updater() {
    // 创建测试集群，包含1个密钥服务器
    let tc = SealTestCluster::new(1, 0).await;

    // 设置更新间隔为1秒
    let update_interval = Duration::from_secs(1);

    // 启动时间戳更新器并获取接收通道
    let mut receiver = tc
        .server()
        .spawn_latest_checkpoint_timestamp_updater(update_interval, None)
        .await;

    // 设置可接受的时间误差（毫秒）
    let tolerance = 20000;

    // 获取当前更新的时间戳
    let timestamp = *receiver.borrow_and_update();
    
    // 获取当前系统时间
    let actual_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    // 验证时间戳与系统时间的差异在容许范围内
    let diff = actual_timestamp - timestamp;
    assert!(diff < tolerance);

    // 等待时间戳更新
    receiver
        .changed()
        .await
        .expect("Failed to get latest timestamp");
        
    // 获取更新后的时间戳
    let new_timestamp = *receiver.borrow_and_update();
    
    // 验证新时间戳大于或等于旧时间戳
    assert!(new_timestamp >= timestamp);
}

/**
 * 测试参考燃气价格更新功能
 * 
 * 此测试验证服务器能够按照指定的时间间隔自动更新参考燃气价格，
 * 并且更新的价格与测试集群中的参考燃气价格一致。
 * 燃气价格对于交易费用的计算和防止DoS攻击非常重要。
 */
#[traced_test]
#[tokio::test]
async fn test_rgp_updater() {
    // 创建测试集群，包含1个密钥服务器
    let tc = SealTestCluster::new(1, 0).await;

    // 设置更新间隔为1秒
    let update_interval = Duration::from_secs(1);

    // 启动参考燃气价格更新器并获取接收通道
    let mut receiver = tc
        .server()
        .spawn_reference_gas_price_updater(update_interval, None)
        .await;

    // 获取当前更新的参考燃气价格
    let price = *receiver.borrow_and_update();
    
    // 验证更新的价格与测试集群中的参考燃气价格一致
    assert_eq!(price, tc.cluster.get_reference_gas_price().await);

    // 等待价格更新
    receiver.changed().await.expect("Failed to get latest rgp");
}
