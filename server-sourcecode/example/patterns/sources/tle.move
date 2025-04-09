// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Time lock encryption pattern:
/// - Anyone can encrypt to time T using key-id [pkg id][bcs::to_bytes(T)].
/// - Anyone can request the key for key-id = T after time T has passed.
///
/// Use cases that can be built on top of this: MEV resilient trading, secure voting.
///
/// Similar patterns:
/// - Time lock encryption with an Update Cap - Anyone can create a shared object UpdatableTle{ id: UID, end_time: u64 }
///   and receive UpdateCap { id: UID, updatable_tle_id: ID }. The associated key-id is [pkg id][id of UpdatableTle].
///   The cap owner can increase the end_time before the end_time has passed. Once the end_time has passed, anyone
///   can request the key.
///
/// 时间锁加密模式：
/// - 任何人都可以使用密钥ID [包ID][bcs::to_bytes(T)]加密到时间T。
/// - 时间T过后，任何人都可以请求密钥ID = T的密钥。
///
/// 可基于此构建的用例：MEV抗性交易、安全投票。
///
/// 类似模式：
/// - 带更新权限的时间锁加密 - 任何人都可以创建共享对象UpdatableTle{ id: UID, end_time: u64 }
///   并接收UpdateCap { id: UID, updatable_tle_id: ID }。关联的密钥ID是[包ID][UpdatableTle的ID]。
///   在end_time到达之前，权限持有者可以增加end_time。一旦end_time过期，任何人都可以请求密钥。
module patterns::tle;

use sui::bcs::{Self, BCS};
use sui::clock;

/// 无访问权限错误
const ENoAccess: u64 = 77;

/////////////////////////////////////
/// Access control
/// key format: [pkg id][bcs::to_bytes(T)]

/// 检查访问策略
/// 验证是否已经到达指定的时间T
/// 
/// 参数:
/// * id: 要检查的密钥ID
/// * c: 时钟对象，提供当前时间
/// 
/// 返回:
/// 如果当前时间已经超过或等于T，则返回true
fun check_policy(id: vector<u8>, c: &clock::Clock): bool {
    let mut prepared: BCS = bcs::new(id);
    let t = prepared.peel_u64();
    let leftovers = prepared.into_remainder_bytes();

    // Check that the time has passed.
    (leftovers.length() == 0) && (c.timestamp_ms() >= t)
}

/// Seal批准函数
/// 验证当前时间是否已经达到或超过指定的时间T
entry fun seal_approve(id: vector<u8>, c: &clock::Clock) {
    assert!(check_policy(id, c), ENoAccess);
}

/// 测试批准功能
#[test]
fun test_approve() {
    let ctx = &mut tx_context::dummy();
    let mut c = clock::create_for_testing(ctx); // time = 0
    let t = 1u64;
    let id = bcs::to_bytes(&t);

    // 0 < 1
    assert!(!check_policy(id, &c), 0);

    // 1 == 1
    c.increment_for_testing(1);
    assert!(check_policy(id, &c), 0);
    // 2 > 1
    c.increment_for_testing(1);
    assert!(check_policy(id, &c), 0);

    c.destroy_for_testing();
}
