// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Owner private data pattern:
/// - Anyone can encrypt any data and store it encrypted as a Sui object.
/// - The owner of the Sui object can always decrypt the data.
///
/// Use cases that can be built on top of this: personal key storage, private NFTs.
///
/// 所有者私有数据模式：
/// - 任何人都可以加密任何数据并将其存储为加密的Sui对象。
/// - Sui对象的所有者始终可以解密数据。
///
/// 可基于此构建的用例：个人密钥存储、私有NFT。
module patterns::private_data;

/// 无访问权限错误
const ENoAccess: u64 = 77;

/// 私有数据对象
/// 存储加密数据及其相关元数据
public struct PrivateData has key, store {
    id: UID,
    creator: address,    // 创建者地址
    nonce: vector<u8>,   // 随机数，确保密钥ID唯一性
    data: vector<u8>,    // 加密的数据
}

/// The encryption key id is [pkg id][creator address][random nonce]
/// - The creator address is used to ensure that only the creator can create an object for that key id
///   (otherwise, others can try to frontrun and create an object for the same key id).
/// - The random nonce is used to ensure that the key id is unique even if the object is transferred to
///   another user.
/// - A single user can create unlimited number of key ids, simply by using different nonces.
/// 
/// 计算加密密钥ID
/// 加密密钥ID的格式为：[包ID][创建者地址][随机数]
/// - 使用创建者地址确保只有创建者可以为该密钥ID创建对象
///   (否则，其他人可能尝试抢先创建具有相同密钥ID的对象)
/// - 随机数用于确保即使对象被转移给其他用户，密钥ID也是唯一的
/// - 单个用户可以通过使用不同的随机数创建无限数量的密钥ID
fun compute_key_id(sender: address, nonce: vector<u8>): vector<u8> {
    let mut blob = sender.to_bytes();
    blob.append(nonce);
    blob
}

/// Store an encrypted data that was encrypted using the above key id.
/// 
/// 存储使用上述密钥ID加密的数据
/// 
/// 参数:
/// * nonce: 随机数
/// * data: 加密后的数据
/// * ctx: 交易上下文
public fun store(nonce: vector<u8>, data: vector<u8>, ctx: &mut TxContext): PrivateData {
    PrivateData {
        id: object::new(ctx),
        creator: ctx.sender(),
        nonce,
        data: data,
    }
}

// Helper function for storing and sending back to sender.
/// 存储并将私有数据发送回发送者的入口函数
entry fun store_entry(nonce: vector<u8>, data: vector<u8>, ctx: &mut TxContext) {
    transfer::transfer(store(nonce, data, ctx), ctx.sender());
}

//////////////////////////////////////////////
/// Access control
/// key format: [pkg id][creator][nonce]
/// 
/// 检查访问策略
/// 验证给定的ID是否具有访问权限
/// 
/// 参数:
/// * id: 要检查的密钥ID
/// * e: 私有数据对象
fun check_policy(id: vector<u8>, e: &PrivateData): bool {
    // Only owner can call this function (enforced by MoveVM)

    // Check the key id is correct.
    let key_id = compute_key_id(e.creator, e.nonce);
    key_id == id
}

/// Seal批准函数
/// 验证给定ID是否有权限访问私有数据
entry fun seal_approve(id: vector<u8>, e: &PrivateData) {
    assert!(check_policy(id, e), ENoAccess);
}

/// 销毁私有数据对象（仅用于测试）
#[test_only]
public fun destroy(e: PrivateData) {
    let PrivateData { id, .. } = e;
    object::delete(id);
}

/// 测试内部策略函数
#[test]
fun test_internal_policy() {
    let ctx = &mut tx_context::dummy();
    let ed = store(b"nonce", b"data", ctx);

    assert!(!check_policy(b"bla", &ed), 0);
    assert!(check_policy(compute_key_id(@0x0, b"nonce"), &ed), 0);
    ed.destroy();
}
