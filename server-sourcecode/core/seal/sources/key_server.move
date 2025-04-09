// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Permissionless registration of a key server:
// - Key server should expose an endpoint /service that returns the official object id of its key server (to prevent
//   impersonation) and a PoP(key=IBE key, m=[key_server_id | IBE public key]).
// - Key server should expose an endpoint /fetch_key that allows users to request a key from the key server.

/// 密钥服务器模块
/// 
/// 该模块实现了密钥服务器的注册和管理功能。
/// 密钥服务器是Seal加密系统中的核心组件，负责存储IBE私钥并为用户提供密钥派生服务。
module seal::key_server;

use std::string::String;
use sui::{bls12381::{G2, g2_from_bytes}, group_ops::Element};

/// 无效的权限令牌错误
const EInvalidCap: u64 = 0;
/// 无效的密钥类型错误
const EInvalidKeyType: u64 = 1;

/// Boneh-Franklin IBE方案使用BLS12-381曲线
const KeyTypeBonehFranklinBLS12381: u8 = 0;

/// 密钥服务器对象
/// 存储服务器名称、URL、密钥类型和公钥
public struct KeyServer has key {
    id: UID,
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
}

/// 密钥服务器的权限令牌
/// 用于验证对密钥服务器的操作权限
public struct Cap has key {
    id: UID,
    key_server_id: ID,
}

/// 注册新的密钥服务器
/// 
/// 参数:
/// * name: 服务器名称
/// * url: 服务器URL
/// * key_type: 密钥类型
/// * pk: 公钥
/// * ctx: 交易上下文
public fun register(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
): Cap {
    // Currently only BLS12-381 is supported.
    assert!(key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
    let _ = g2_from_bytes(&pk);

    let key_server = KeyServer {
        id: object::new(ctx),
        name,
        url,
        key_type,
        pk,
    };

    let cap = Cap {
        id: object::new(ctx),
        key_server_id: object::id(&key_server),
    };

    transfer::share_object(key_server);
    cap
}

/// 注册密钥服务器并将权限令牌转移给调用者
/// 
/// 参数:
/// * name: 服务器名称
/// * url: 服务器URL
/// * key_type: 密钥类型
/// * pk: 公钥
/// * ctx: 交易上下文
entry fun register_and_transfer(
    name: String,
    url: String,
    key_type: u8,
    pk: vector<u8>,
    ctx: &mut TxContext,
) {
    let cap = register(name, url, key_type, pk, ctx);
    transfer::transfer(cap, ctx.sender());
}

/// 获取密钥服务器名称
public fun name(s: &KeyServer): String {
    s.name
}

/// 获取密钥服务器URL
public fun url(s: &KeyServer): String {
    s.url
}

/// 获取密钥服务器密钥类型
public fun key_type(s: &KeyServer): u8 {
    s.key_type
}

/// 获取密钥服务器公钥
public fun pk(s: &KeyServer): &vector<u8> {
    &s.pk
}

/// 获取密钥服务器ID
public fun id(s: &KeyServer): &UID {
    &s.id
}

/// 将密钥服务器公钥解析为BLS12-381 G2元素
public fun pk_as_bf_bls12381(s: &KeyServer): Element<G2> {
    assert!(s.key_type == KeyTypeBonehFranklinBLS12381, EInvalidKeyType);
    g2_from_bytes(&s.pk)
}

/// 更新密钥服务器URL
/// 
/// 参数:
/// * s: 密钥服务器引用
/// * cap: 权限令牌
/// * url: 新的URL
public fun update(s: &mut KeyServer, cap: &Cap, url: String) {
    assert!(object::id(s) == cap.key_server_id, EInvalidCap);
    s.url = url;
}

/// 销毁权限令牌（仅用于测试）
#[test_only]
public fun destroy_cap(c: Cap) {
    let Cap { id, .. } = c;
    object::delete(id);
}

/// 测试密钥服务器功能
#[test]
fun test_flow() {
    use sui::test_scenario::{Self, next_tx, ctx};
    use sui::bls12381::{g2_generator};
    use std::string;

    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    let pk = g2_generator();
    let pk_bytes = *pk.bytes();
    let cap = register(
        string::utf8(b"mysten"),
        string::utf8(b"https::/mysten-labs.com"),
        0,
        pk_bytes,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);

    let mut s: KeyServer = test_scenario::take_shared(&scenario);
    assert!(name(&s) == string::utf8(b"mysten"), 0);
    assert!(url(&s) == string::utf8(b"https::/mysten-labs.com"), 0);
    assert!(pk(&s) == pk.bytes(), 0);
    s.update(&cap, string::utf8(b"https::/mysten-labs2.com"));
    assert!(url(&s) == string::utf8(b"https::/mysten-labs2.com"), 0);

    test_scenario::return_shared(s);
    destroy_cap(cap);
    test_scenario::end(scenario);
}
