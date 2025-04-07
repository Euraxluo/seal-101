// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// 基于许可名单模式
// Based on the allowlist pattern

/// @title 许可名单模块
/// @notice 提供一种访问控制机制，允许特定地址访问特定资源
module walrus::allowlist;

use std::string::String;
use sui::dynamic_field as df;
use walrus::utils::is_prefix;

/// @notice 错误码：无效的权限凭证
const EInvalidCap: u64 = 0;
/// @notice 错误码：没有访问权限
const ENoAccess: u64 = 1;
/// @notice 错误码：地址已存在于许可名单中
const EDuplicate: u64 = 2;
/// @notice 标记常量，用于动态字段
const MARKER: u64 = 3;

/// @notice 许可名单结构，存储允许访问的地址列表
public struct Allowlist has key {
    id: UID,
    name: String,
    list: vector<address>,
}

/// @notice 管理员权限凭证，用于管理许可名单
public struct Cap has key {
    id: UID,
    allowlist_id: ID,
}

//////////////////////////////////////////
/////// 简单的许可名单及其管理员凭证

/// 创建一个许可名单及其管理员凭证
/// 相关的密钥ID格式为 [包ID]::[许可名单ID][随机数]，对于任意随机数
/// （因此可以为同一个许可名单创建多个密钥ID）
///
/// @param name - 许可名单名称
/// @param ctx - 交易上下文
/// @return 管理员权限凭证
public fun create_allowlist(name: String, ctx: &mut TxContext): Cap {
    let allowlist = Allowlist {
        id: object::new(ctx),
        list: vector::empty(),
        name: name,
    };
    let cap = Cap {
        id: object::new(ctx),
        allowlist_id: object::id(&allowlist),
    };
    transfer::share_object(allowlist);
    cap
}

/// 创建许可名单并将管理员凭证发送给调用者的入口函数
/// （简化CLI程序构建流程）
entry fun create_allowlist_entry(name: String, ctx: &mut TxContext) {
    transfer::transfer(create_allowlist(name, ctx), ctx.sender());
}

/// 向许可名单添加地址
/// 
/// @param allowlist - 要修改的许可名单
/// @param cap - 管理员权限凭证
/// @param account - 要添加的地址
public fun add(allowlist: &mut Allowlist, cap: &Cap, account: address) {
    assert!(cap.allowlist_id == object::id(allowlist), EInvalidCap);
    assert!(!allowlist.list.contains(&account), EDuplicate);
    allowlist.list.push_back(account);
}

/// 从许可名单中移除地址
/// 
/// @param allowlist - 要修改的许可名单
/// @param cap - 管理员权限凭证
/// @param account - 要移除的地址
public fun remove(allowlist: &mut Allowlist, cap: &Cap, account: address) {
    assert!(cap.allowlist_id == object::id(allowlist), EInvalidCap);
    allowlist.list = allowlist.list.filter!(|x| x != account); // TODO: 实现更高效的方法?
}

//////////////////////////////////////////////////////////
/// 访问控制
/// 密钥格式: [包ID]::[许可名单ID][随机数]
/// (替代密钥格式: [包ID]::[创建者地址][随机数] - 参见 private_data.move)

/// 获取许可名单的命名空间
/// 
/// @param allowlist - 许可名单
/// @return 表示命名空间的字节向量
public fun namespace(allowlist: &Allowlist): vector<u8> {
    allowlist.id.to_bytes()
}

/// 检查调用者是否有权限访问特定ID
/// 所有在许可名单中的地址都可以访问具有该许可名单前缀的所有ID
/// 
/// @param caller - 调用者地址
/// @param id - 要访问的ID
/// @param allowlist - 许可名单
/// @return 是否批准访问
fun approve_internal(caller: address, id: vector<u8>, allowlist: &Allowlist): bool {
    // 检查ID是否具有正确的前缀
    let namespace = namespace(allowlist);
    if (!is_prefix(namespace, id)) {
        return false
    };

    // 检查用户是否在许可名单中
    allowlist.list.contains(&caller)
}

/// 检查调用者是否有权限访问特定ID的入口函数
/// 
/// @param id - 要访问的ID
/// @param allowlist - 许可名单
/// @param ctx - 交易上下文
entry fun seal_approve(id: vector<u8>, allowlist: &Allowlist, ctx: &TxContext) {
    assert!(approve_internal(ctx.sender(), id, allowlist), ENoAccess);
}

/// 将数据块封装为Sui对象并附加到许可名单
/// 
/// @param allowlist - 要修改的许可名单
/// @param cap - 管理员权限凭证
/// @param blob_id - 数据块ID
public fun publish(allowlist: &mut Allowlist, cap: &Cap, blob_id: String) {
    assert!(cap.allowlist_id == object::id(allowlist), EInvalidCap);
    df::add(&mut allowlist.id, blob_id, MARKER);
}

#[test_only]
/// 仅测试使用：创建新的许可名单
public fun new_allowlist_for_testing(ctx: &mut TxContext): Allowlist {
    use std::string::utf8;

    Allowlist {
        id: object::new(ctx),
        name: utf8(b"test"),
        list: vector::empty(),
    }
}

#[test_only]
/// 仅测试使用：创建新的管理员凭证
public fun new_cap_for_testing(ctx: &mut TxContext, allowlist: &Allowlist): Cap {
    Cap {
        id: object::new(ctx),
        allowlist_id: object::id(allowlist),
    }
}

#[test_only]
/// 仅测试使用：销毁许可名单和管理员凭证
public fun destroy_for_testing(allowlist: Allowlist, cap: Cap) {
    let Allowlist { id, .. } = allowlist;
    object::delete(id);
    let Cap { id, .. } = cap;
    object::delete(id);
}
