// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// KeyRequest pattern:
/// - Policy is checked onchain, and if granted, a KeyRequest object is returned to the user.
/// - The user can then use the KeyRequest object to access the associated key using Seal.
///
/// Dapp developers need to define how to contrust KeyRequest, and implement seal_approve that
/// only calls verify. Seal is agnostic to the actual policy.
///
/// Use cases that can be built on top of this: pay per key request, complex policies in which
/// safety during dryRun must be guaranteed.
///
/// See a test below for an example of how to use this pattern with a whitelist.
///
/// 密钥请求模式：
/// - 策略在链上检查，如果授权通过，则向用户返回KeyRequest对象。
/// - 用户可以使用KeyRequest对象通过Seal访问关联的密钥。
///
/// Dapp开发者需要定义如何构建KeyRequest，并实现只调用verify的seal_approve。
/// Seal对实际策略是不可知的。
///
/// 可基于此构建的用例：按密钥请求付费、需要在dryRun期间保证安全性的复杂策略。
///
/// 下面的测试展示了如何将此模式与白名单一起使用的示例。
module patterns::key_request {
    use std::ascii::String;
    use std::type_name;
    use sui::clock::Clock;

    /// KeyRequest object has all the info needed to access a key.
    /// 
    /// KeyRequest对象包含访问密钥所需的所有信息
    public struct KeyRequest has key, store {
        id: UID,
        package: String,  // 包地址（十六进制）
        inner_id: vector<u8>, // 内部ID
        user: address,    // 用户地址
        valid_till: u64,  // 有效期（时间戳，毫秒）
    }

    /// Any contract can create a KeyRequest object associated with a given witness T (inaccessible to other contracts).
    /// ttl is the number of milliseconds after which the KeyRequest object expires.
    /// 
    /// 请求密钥
    /// 任何合约都可以创建与给定见证类型T关联的KeyRequest对象（其他合约无法访问）
    /// ttl是KeyRequest对象过期后的毫秒数
    /// 
    /// 参数:
    /// * _w: 见证类型实例
    /// * id: 内部ID
    /// * user: 用户地址
    /// * c: 时钟对象
    /// * ttl: 有效期（毫秒）
    /// * ctx: 交易上下文
    public fun request_key<T: drop>(
        _w: T,
        id: vector<u8>,
        user: address,
        c: &Clock,
        ttl: u64,
        ctx: &mut TxContext,
    ): KeyRequest {
        // The package of the caller (via the witness T).
        let package = type_name::get_with_original_ids<T>().get_address();
        KeyRequest {
            id: object::new(ctx),
            package,
            inner_id: id,
            user,
            valid_till: c.timestamp_ms() + ttl,
        }
    }

    /// 销毁KeyRequest对象
    public fun destroy(req: KeyRequest) {
        let KeyRequest { id, .. } = req;
        object::delete(id);
    }

    /// Verify that the KeyRequest is consistent with the given parameters, and that it has not expired.
    /// The dapp needs to call only this function in seal_approve.
    /// 
    /// 验证KeyRequest
    /// 验证KeyRequest是否与给定参数一致，且未过期
    /// Dapp需要在seal_approve中仅调用此函数
    /// 
    /// 参数:
    /// * req: KeyRequest对象
    /// * _w: 见证类型实例
    /// * id: 内部ID
    /// * user: 用户地址
    /// * c: 时钟对象
    /// 
    /// 返回:
    /// 如果验证通过，则返回true
    public fun verify<T: drop>(
        req: &KeyRequest,
        _w: T,
        id: vector<u8>,
        user: address,
        c: &Clock,
    ): bool {
        let package = type_name::get_with_original_ids<T>().get_address();
        (req.package == package) && (req.inner_id == id) && (req.user == user) && (c.timestamp_ms() <= req.valid_till)
    }
}

/// Example of how to use the KeyRequest pattern with a whitelist.
/// 
/// 如何将密钥请求模式与白名单一起使用的示例
#[test_only]
module patterns::key_request_whitelist_test {
    use patterns::key_request as kro;
    use sui::clock::Clock;

    /// 无访问权限错误
    const ENoAccess: u64 = 1;

    /// 有效期：1分钟（毫秒）
    const TTL: u64 = 60_000; // 1 minute

    /// 白名单对象
    /// 存储允许访问的用户地址列表
    public struct Whitelist has key {
        id: UID,
        users: vector<address>, // 白名单用户列表
    }

    // Just a static whitelist for the example, see the Whitelist pattern for a dynamic one.
    /// 创建白名单
    /// 这只是一个静态白名单示例，完整的动态白名单请参考Whitelist模式
    public fun create_whitelist(users: vector<address>, ctx: &mut TxContext): Whitelist {
        Whitelist {
            id: object::new(ctx),
            users: users,
        }
    }

    /// 销毁白名单（仅用于测试）
    #[test_only]
    public fun destroy_for_testing(wl: Whitelist) {
        let Whitelist { id, .. } = wl;
        object::delete(id);
    }

    /// 用于密钥请求的见证类型
    public struct WITNESS has drop {}

    /// Users request access using request_access.
    /// 
    /// 请求访问权限
    /// 用户通过request_access请求访问权限
    /// 
    /// 参数:
    /// * wl: 白名单对象
    /// * c: 时钟对象
    /// * ctx: 交易上下文
    public fun request_access(wl: &Whitelist, c: &Clock, ctx: &mut TxContext): kro::KeyRequest {
        assert!(wl.users.contains(&ctx.sender()), ENoAccess);
        kro::request_key(WITNESS {}, wl.id.to_bytes(), ctx.sender(), c, TTL, ctx)
    }

    /// Seal only checks consistency of the request using req.verify.
    /// The actual policy is checked in request_access above.
    /// 
    /// Seal批准函数
    /// Seal只使用req.verify检查请求的一致性
    /// 实际策略在上面的request_access中检查
    entry fun seal_approve(id: vector<u8>, req: &kro::KeyRequest, c: &Clock, ctx: &TxContext) {
        assert!(req.verify(WITNESS {}, id, ctx.sender(), c), ENoAccess);
    }

    /// 端到端测试
    #[test]
    fun test_e2e() {
        use sui::clock;

        let ctx = &mut tx_context::dummy(); // sender = 0x0
        let c = clock::create_for_testing(ctx); // time = 0

        let wl = create_whitelist(vector[@0x0, @0x1], ctx);
        let kr = request_access(&wl, &c, ctx);
        seal_approve(object::id(&wl).to_bytes(), &kr, &c, ctx);

        kr.destroy();
        destroy_for_testing(wl);
        c.destroy_for_testing();
    }
}
