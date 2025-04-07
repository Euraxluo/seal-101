// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// 基于订阅模式
// Based on the subscription pattern.
// TODO: 完善文档并添加测试用例

/// @title 订阅模块
/// @notice 提供基于时间和付费的服务订阅机制
module walrus::subscription;

use std::string::String;
use sui::{clock::Clock, coin::Coin, dynamic_field as df, sui::SUI};
use walrus::utils::is_prefix;

/// @notice 错误码：无效的权限凭证
const EInvalidCap: u64 = 0;
/// @notice 错误码：无效的支付金额
const EInvalidFee: u64 = 1;
/// @notice 错误码：没有访问权限
const ENoAccess: u64 = 2;
/// @notice 标记常量，用于动态字段
const MARKER: u64 = 3;

/// @notice 服务结构，定义服务的费用、有效期和所有者
public struct Service has key {
    id: UID,
    fee: u64,          // 订阅费用
    ttl: u64,          // 订阅有效期（毫秒）
    owner: address,    // 服务所有者
    name: String,      // 服务名称
}

/// @notice 订阅凭证，记录订阅的服务ID和创建时间
public struct Subscription has key {
    id: UID,
    service_id: ID,    // 订阅的服务ID
    created_at: u64,   // 订阅创建时间（毫秒）
}

/// @notice 管理员权限凭证，用于管理服务
public struct Cap has key {
    id: UID,
    service_id: ID,
}

//////////////////////////////////////////
/////// 简单的服务实现

/// 创建一个服务及其管理员凭证
/// 相关的密钥ID格式为 [包ID]::[服务ID][随机数]，对于任意随机数
/// （因此可以为同一个服务创建多个密钥ID）
///
/// @param fee - 服务订阅费用
/// @param ttl - 订阅有效期（毫秒）
/// @param name - 服务名称
/// @param ctx - 交易上下文
/// @return 管理员权限凭证
public fun create_service(fee: u64, ttl: u64, name: String, ctx: &mut TxContext): Cap {
    let service = Service {
        id: object::new(ctx),
        fee: fee,
        ttl: ttl,
        owner: ctx.sender(),
        name: name,
    };
    let cap = Cap {
        id: object::new(ctx),
        service_id: object::id(&service),
    };
    transfer::share_object(service);
    cap
}

/// 创建服务并共享它的入口函数（简化CLI程序构建流程）
///
/// @param fee - 服务订阅费用
/// @param ttl - 订阅有效期（毫秒）
/// @param name - 服务名称
/// @param ctx - 交易上下文
entry fun create_service_entry(fee: u64, ttl: u64, name: String, ctx: &mut TxContext) {
    transfer::transfer(create_service(fee, ttl, name, ctx), ctx.sender());
}

/// 订阅服务
/// 
/// @param fee - 支付的SUI代币
/// @param service - 要订阅的服务
/// @param c - 时钟对象，用于获取当前时间
/// @param ctx - 交易上下文
/// @return 订阅凭证
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

/// 转移订阅凭证给其他地址
/// 
/// @param sub - 要转移的订阅凭证
/// @param to - 接收地址
public fun transfer(sub: Subscription, to: address) {
    transfer::transfer(sub, to);
}

#[test_only]
/// 仅测试使用：销毁服务和订阅
public fun destroy_for_testing(ser: Service, sub: Subscription) {
    let Service { id, .. } = ser;
    object::delete(id);
    let Subscription { id, .. } = sub;
    object::delete(id);
}

//////////////////////////////////////////////////////////
/// 访问控制
/// 密钥格式: [包ID]::[服务ID][随机数]

/// 检查订阅凭证是否有效且可以访问特定ID
/// 
/// @param id - 要访问的ID
/// @param sub - 订阅凭证
/// @param service - 服务对象
/// @param c - 时钟对象，用于获取当前时间
/// @return 是否批准访问
fun approve_internal(id: vector<u8>, sub: &Subscription, service: &Service, c: &Clock): bool {
    // 检查订阅的服务ID是否与提供的服务匹配
    if (object::id(service) != sub.service_id) {
        return false
    };
    // 检查订阅是否已过期
    if (c.timestamp_ms() > sub.created_at + service.ttl) {
        return false
    };

    // 检查ID是否具有正确的前缀（服务ID的字节表示）
    is_prefix(service.id.to_bytes(), id)
}

/// 检查订阅凭证是否有效且可以访问特定ID的入口函数
/// 
/// @param id - 要访问的ID
/// @param sub - 订阅凭证
/// @param service - 服务对象
/// @param c - 时钟对象，用于获取当前时间
entry fun seal_approve(id: vector<u8>, sub: &Subscription, service: &Service, c: &Clock) {
    assert!(approve_internal(id, sub, service, c), ENoAccess);
}

/// 将数据块封装为Sui对象并附加到服务
/// 
/// @param service - 要修改的服务
/// @param cap - 管理员权限凭证
/// @param blob_id - 数据块ID
public fun publish(service: &mut Service, cap: &Cap, blob_id: String) {
    assert!(cap.service_id == object::id(service), EInvalidCap);
    df::add(&mut service.id, blob_id, MARKER);
}
