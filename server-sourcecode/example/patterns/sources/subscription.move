// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Subscription pattern:
/// - Anyone can create a service that requires a subscription.
/// - Anyone can buy a subscription to the service for a certain period.
/// - Anyone with an active subscription can access its service related keys.
///
/// Use cases that can be built on top of this: subscription based access to content.
///
/// 订阅模式：
/// - 任何人都可以创建需要订阅的服务。
/// - 任何人都可以购买一定期限的服务订阅。
/// - 任何拥有有效订阅的人都可以访问其服务相关的密钥。
///
/// 可基于此构建的用例：基于订阅的内容访问服务。
module patterns::subscription;

use sui::clock::Clock;
use sui::coin::Coin;
use sui::sui::SUI;

/// 无效费用错误
const EInvalidFee: u64 = 12;
/// 无访问权限错误
const ENoAccess: u64 = 77;

/// 服务对象
/// 定义需要订阅的服务及其属性
public struct Service has key {
    id: UID,
    fee: u64,           // 订阅费用
    ttl: u64,           // 订阅有效期（毫秒）
    owner: address,     // 服务所有者地址
}

/// Subscription can only be transferred to another address (but not stored / shared / received, etc).
/// 
/// 订阅对象
/// 表示用户对特定服务的订阅
/// 订阅只能转移给另一个地址（不能存储/共享/接收等）
public struct Subscription has key {
    id: UID,
    service_id: ID,      // 所订阅服务的ID
    created_at: u64,     // 创建时间戳（毫秒）
}

//////////////////////////////////////////
/////// Simple a service

/// Create a service.
/// The associated key-ids are [pkg id][service id][nonce] for any nonce (thus
/// many key-ids can be created for the same service).
/// 
/// 创建服务
/// 关联的密钥ID格式为：[包ID][服务ID][随机数]
/// 对于任何随机数都可以创建密钥ID（因此可以为同一服务创建多个密钥ID）
/// 
/// 参数:
/// * fee: 订阅费用
/// * ttl: 订阅有效期（毫秒）
/// * ctx: 交易上下文
public fun create_service(fee: u64, ttl: u64, ctx: &mut TxContext): Service {
    Service {
        id: object::new(ctx),
        fee: fee,
        ttl: ttl,
        owner: ctx.sender(),
    }
}

// convenience function to create a service and share it (simpler ptb for cli)
/// 创建并共享服务的入口函数
/// 为CLI提供更简单的交易构建方式
entry fun create_service_entry(fee: u64, ttl: u64, ctx: &mut TxContext) {
    transfer::share_object(create_service(fee, ttl, ctx));
}

/// 订阅服务
/// 
/// 参数:
/// * fee: 支付的SUI代币
/// * service: 要订阅的服务
/// * c: 时钟对象，用于记录订阅时间
/// * ctx: 交易上下文
/// 
/// 返回:
/// 新创建的订阅对象
public fun subscribe(
    fee: Coin<SUI>,
    service: &Service,
    c: &Clock,
    ctx: &mut TxContext,
): Subscription {
    assert!(fee.value() == service.fee, EInvalidFee);
    transfer::public_transfer(fee, service.owner);
    Subscription {
        id: object::new(ctx),
        service_id: object::id(service),
        created_at: c.timestamp_ms(),
    }
}

/// 转移订阅给指定地址
public fun transfer(sub: Subscription, to: address) {
    transfer::transfer(sub, to);
}

/// 销毁服务和订阅对象（仅用于测试）
#[test_only]
public fun destroy_for_testing(ser: Service, sub: Subscription) {
    let Service { id, .. } = ser;
    object::delete(id);
    let Subscription { id, .. } = sub;
    object::delete(id);
}

//////////////////////////////////////////////////////////
/// Access control
/// key format: [pkg id][service id][random nonce]

/// All addresses can access all IDs with the prefix of the service
/// 
/// 检查访问策略
/// 验证给定的ID和订阅是否有权访问服务
/// 所有地址都可以访问以服务ID为前缀的所有密钥ID
/// 
/// 参数:
/// * id: 要检查的密钥ID
/// * sub: 订阅对象
/// * service: 服务对象
/// * c: 时钟对象，用于验证订阅是否过期
fun check_policy(id: vector<u8>, sub: &Subscription, service: &Service, c: &Clock): bool {
    if (object::id(service) != sub.service_id) {
        return false
    };
    if (c.timestamp_ms() > sub.created_at + service.ttl) {
        return false
    };

    // Check if the id has the right prefix
    let namespace = service.id.to_bytes();
    let mut i = 0;
    if (namespace.length() > id.length()) {
        return false
    };
    while (i < namespace.length()) {
        if (namespace[i] != id[i]) {
            return false
        };
        i = i + 1;
    };
    true
}

/// Seal批准函数
/// 验证给定ID和订阅是否有权访问服务
entry fun seal_approve(id: vector<u8>, sub: &Subscription, service: &Service, c: &Clock) {
    assert!(check_policy(id, sub, service, c), ENoAccess);
}

/// 测试批准功能
#[test]
fun test_approve() {
    use sui::clock;
    use sui::coin;

    let ctx = &mut tx_context::dummy();
    let mut c = clock::create_for_testing(ctx); // time = 0
    let coin = coin::mint_for_testing<SUI>(10, ctx);

    let ser = create_service(10, 2, ctx);
    let sub = subscribe(coin, &ser, &c, ctx);

    let mut obj_id = object::id(&ser).to_bytes();
    obj_id.push_back(11);

    // Work for time 0
    assert!(check_policy(obj_id, &sub, &ser, &c));
    c.increment_for_testing(1);
    assert!(check_policy(obj_id, &sub, &ser, &c));
    // time 3 should fail
    c.increment_for_testing(2);
    assert!(!check_policy(obj_id, &sub, &ser, &c));

    destroy_for_testing(ser, sub);
    c.destroy_for_testing();
}
