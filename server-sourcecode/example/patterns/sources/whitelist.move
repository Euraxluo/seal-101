// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Whitelist pattern:
/// - Anyone can create a whitelist which defines a unique key-id.
/// - Anyone can encrypt to that key-id.
/// - Anyone on the whitelist can request the key associated with the whitelist's key-id,
///   allowing it to decrypt all data encrypted to that key-id.
///
/// Use cases that can be built on top of this: subscription based access to encrypted files.
///
/// Similar patterns:
/// - Whitelist with temporary privacy: same whitelist as below, but also store created_at: u64.
///   After a fixed TTL anyone can access the key, regardless of being on the whitelist.
///   Temporary privacy can be useful for compliance reasons, e.g., GDPR.
///
/// 白名单模式：
/// - 任何人都可以创建定义唯一密钥ID的白名单。
/// - 任何人都可以使用该密钥ID进行加密。
/// - 白名单上的任何人都可以请求与白名单密钥ID关联的密钥，
///   允许其解密所有使用该密钥ID加密的数据。
///
/// 可基于此构建的用例：基于订阅的加密文件访问。
///
/// 类似模式：
/// - 临时隐私白名单：与下面相同的白名单，但还存储created_at: u64。
///   在固定TTL后，任何人都可以访问密钥，无论是否在白名单上。
///   临时隐私对于合规原因（如GDPR）可能很有用。
module patterns::whitelist;

use sui::table;

/// 无访问权限错误
const ENoAccess: u64 = 1;
/// 无效的Cap错误
const EInvalidCap: u64 = 2;
/// 重复地址错误
const EDuplicate: u64 = 3;
/// 不在白名单中错误
const ENotInWhitelist: u64 = 4;

/// 白名单结构
/// 存储被允许访问的地址列表
public struct Whitelist has key {
    id: UID,
    addresses: table::Table<address, bool>,
}

/// 白名单管理凭证
/// 用于管理白名单（添加/删除地址）
public struct Cap has key {
    id: UID,
    wl_id: ID,
}

//////////////////////////////////////////
/////// Simple whitelist with an admin cap
/// 带管理员凭证的简单白名单

/// Create a whitelist with an admin cap.
/// The associated key-ids are [pkg id][whitelist id][nonce] for any nonce (thus
/// many key-ids can be created for the same whitelist).
///
/// 创建白名单及其管理凭证
/// 关联的密钥ID格式为[包ID][白名单ID][随机数]（因此可以为同一白名单创建多个密钥ID）
public fun create_whitelist(ctx: &mut TxContext): (Cap, Whitelist) {
    let wl = Whitelist {
        id: object::new(ctx),
        addresses: table::new(ctx),
    };
    let cap = Cap {
        id: object::new(ctx),
        wl_id: object::id(&wl),
    };
    (cap, wl)
}

// Helper function for creating a whitelist and send it back to sender.
/// 创建白名单的入口函数
/// 创建白名单并将其返回给发送者
entry fun create_whitelist_entry(ctx: &mut TxContext) {
    let (cap, wl) = create_whitelist(ctx);
    transfer::share_object(wl);
    transfer::transfer(cap, ctx.sender());
}

/// 添加地址到白名单
/// 
/// 参数:
/// * wl: 白名单对象
/// * cap: 白名单管理凭证
/// * account: 要添加的账户地址
public fun add(wl: &mut Whitelist, cap: &Cap, account: address) {
    assert!(cap.wl_id == object::id(wl), EInvalidCap);
    assert!(!wl.addresses.contains(account), EDuplicate);
    wl.addresses.add(account, true);
}

/// 从白名单中移除地址
/// 
/// 参数:
/// * wl: 白名单对象
/// * cap: 白名单管理凭证
/// * account: 要移除的账户地址
public fun remove(wl: &mut Whitelist, cap: &Cap, account: address) {
    assert!(cap.wl_id == object::id(wl), EInvalidCap);
    assert!(wl.addresses.contains(account), ENotInWhitelist);
    wl.addresses.remove(account);
}

//////////////////////////////////////////////////////////
/// Access control
/// key format: [pkg id][whitelist id][random nonce]
/// (Alternative key format: [pkg id][creator address][random nonce] - see private_data.move)
/// 
/// 访问控制
/// 密钥格式: [包ID][白名单ID][随机数]
/// (替代密钥格式: [包ID][创建者地址][随机数] - 参见private_data.move)

/// All whitelisted addresses can access all IDs with the prefix of the whitelist
/// 
/// 检查策略
/// 所有白名单地址都可以访问具有白名单前缀的所有ID
/// 
/// 参数:
/// * caller: 调用者地址
/// * id: 密钥ID
/// * wl: 白名单对象
/// 
/// 返回:
/// 如果调用者在白名单中且ID前缀正确，则返回true
fun check_policy(caller: address, id: vector<u8>, wl: &Whitelist): bool {
    // Check if the id has the right prefix
    // 检查ID是否具有正确的前缀
    let prefix = wl.id.to_bytes();
    let mut i = 0;
    if (prefix.length() > id.length()) {
        return false
    };
    while (i < prefix.length()) {
        if (prefix[i] != id[i]) {
            return false
        };
        i = i + 1;
    };

    // Check if user is in the whitelist
    // 检查用户是否在白名单中
    wl.addresses.contains(caller)
}

/// Seal批准函数
/// 如果调用者在白名单中且ID前缀正确，则批准
entry fun seal_approve(id: vector<u8>, wl: &Whitelist, ctx: &TxContext) {
    assert!(check_policy(ctx.sender(), id, wl), ENoAccess);
}

/// 用于测试的销毁函数
#[test_only]
public fun destroy_for_testing(wl: Whitelist, cap: Cap) {
    let Whitelist { id, addresses } = wl;
    addresses.drop();
    object::delete(id);
    let Cap { id, .. } = cap;
    object::delete(id);
}

/// 测试批准功能
#[test]
fun test_approve() {
    let ctx = &mut tx_context::dummy();
    let (cap, mut wl) = create_whitelist(ctx);
    wl.add(&cap, @0x1);
    wl.remove(&cap, @0x1);
    wl.add(&cap, @0x2);

    // Fail for invalid id
    // 无效ID失败
    assert!(!check_policy(@0x2, b"123", &wl), 1);
    // Work for valid id, user 2 is in the whitelist
    // 对有效ID有效，用户2在白名单中
    let mut obj_id = object::id(&wl).to_bytes();
    obj_id.push_back(11);
    assert!(check_policy(@0x2, obj_id, &wl), 1);
    // Fail for user 1
    // 用户1失败
    assert!(!check_policy(@0x1, obj_id, &wl), 1);

    destroy_for_testing(wl, cap);
}
