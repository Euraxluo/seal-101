// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Account based encryption:
/// - Anyone can encrypt to address B using key-id [pkg id]::[bcs::to_bytes(B)].
/// - Only the owner of account B can access the associated key.
///
/// Use cases that can be built on top of this: offchain secure messaging.
///
/// 基于账户的加密：
/// - 任何人都可以使用密钥ID [包ID]::[bcs::to_bytes(B)]向地址B加密内容。
/// - 只有账户B的所有者可以访问关联的密钥。
///
/// 可基于此构建的用例：链下安全消息传递。
module patterns::account_based;

use sui::bcs;

/// 无访问权限错误
const ENoAccess: u64 = 1;

/////////////////////////////////////
/// Access control
/// key format: [pkg id][bcs::to_bytes(B)] for address B

/// 检查访问策略
/// 验证调用者是否是指定的账户所有者
/// 
/// 参数:
/// * id: 要检查的密钥ID
/// * ctx: 交易上下文
/// 
/// 返回:
/// 如果调用者是指定的账户所有者，则返回true
fun check_policy(id: vector<u8>, ctx: &TxContext): bool {
    let caller_bytes = bcs::to_bytes(&ctx.sender());
    id == caller_bytes
}

/// Seal批准函数
/// 验证调用者是否可以访问指定的密钥ID
entry fun seal_approve(id: vector<u8>, ctx: &TxContext) {
    assert!(check_policy(id, ctx), ENoAccess);
}

/// 测试检查策略功能
#[test]
fun test_check_policy() {
    let ctx = tx_context::dummy();
    let sender = ctx.sender();
    let id = bcs::to_bytes(&sender);
    assert!(check_policy(id, &ctx), 0);

    let id = bcs::to_bytes(&0x0232);
    assert!(!check_policy(id, &ctx), 0);
}
