// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Voting pattern:
/// - Anyone can create a vote with a set of voters.
/// - The voters can submit their encrypted votes.
/// - After all the voters have submitted votes, anyone can retrieve the encryption keys and submit them. The votes are then decrypted on-chain.
///
/// This is an example of on-chain decryption. Other use cases of this include auctions, timelocked voting, etc.
///
/// 投票模式：
/// - 任何人都可以创建一个包含一组投票者的投票。
/// - 投票者可以提交他们的加密投票。
/// - 在所有投票者提交投票后，任何人都可以检索加密密钥并提交它们。投票随后在链上解密。
///
/// 这是链上解密的一个示例。其他使用案例包括拍卖、时间锁定投票等。
module patterns::voting;

use seal::bf_hmac_encryption::{EncryptedObject, VerifiedDerivedKey, PublicKey, decrypt};

/// 无效投票错误
const EInvalidVote: u64 = 1;
/// 投票未完成错误
const EVoteNotDone: u64 = 2;
/// 已经最终确定错误
const EAlreadyFinalized: u64 = 3;

/// This represents a vote.
/// 
/// 这代表一个投票
public struct Vote has key {
    /// The id of a vote is the id of the object.
    /// 投票的ID是对象的ID
    id: UID,
    /// The eligble voters of the vote.
    /// 有资格投票的选民
    voters: vector<address>,
    /// This holds the encrypted votes assuming the same order as the `voters` vector.
    /// 这保存加密的投票，假设顺序与`voters`向量相同
    votes: vector<Option<EncryptedObject>>,
    /// This will be set after the vote is finalised. The vote options are represented by a Option<u8> which is None if the vote was invalid.
    /// 这将在投票最终确定后设置。投票选项由Option<u8>表示，如果投票无效，则为None
    result: Option<vector<Option<u8>>>,
    /// The key servers that must be used for the encryption of the votes.
    /// 必须用于投票加密的密钥服务器
    key_servers: vector<ID>,
    /// The threshold for the vote.
    /// 投票的阈值
    threshold: u8,
}

// The id of a vote is the id of the object.
/// 获取投票的ID
public fun id(v: &Vote): vector<u8> {
    object::id(v).to_bytes()
}

/// 用于测试的销毁函数
#[test_only]
public fun destroy_for_testing(v: Vote) {
    let Vote { id, .. } = v;
    object::delete(id);
}

/// Create a vote.
/// The associated key-ids are [pkg id][vote id].
///
/// 创建投票
/// 关联的密钥ID格式为[包ID][投票ID]
public fun create_vote(
    voters: vector<address>,
    key_servers: vector<ID>,
    threshold: u8,
    ctx: &mut TxContext,
): Vote {
    assert!(threshold <= key_servers.length() as u8);
    Vote {
        id: object::new(ctx),
        voters,
        key_servers,
        threshold,
        votes: vector::tabulate!(voters.length(), |_| option::none()),
        result: option::none(),
    }
}

/// Cast a vote.
/// The encrypted object should be an encryption of a single u8 and have the senders address as aad.
///
/// 投票
/// 加密对象应该是单个u8的加密，并将发送者地址作为AAD（额外认证数据）
public fun cast_vote(vote: &mut Vote, encrypted_vote: EncryptedObject, ctx: &mut TxContext) {
    // The voter id must be put as aad to ensure that an encrypted vote cannot be copied and cast by another voter.
    // 投票者ID必须作为AAD，以确保加密投票不能被另一个投票者复制和投票
    assert!(encrypted_vote.aad().borrow() == ctx.sender().to_bytes(), EInvalidVote);

    // All encrypted vote must have been encrypted using the same key servers and the same threshold.
    // We could allow the order of the key servers to be different, but for the sake of simplicity, we also require the same order.
    // 所有加密投票必须使用相同的密钥服务器和相同的阈值进行加密
    // 我们可以允许密钥服务器的顺序不同，但为了简单起见，我们也要求相同的顺序
    assert!(encrypted_vote.services() == vote.key_servers.map_ref!(|id| id.to_address()));
    assert!(encrypted_vote.threshold() == vote.threshold);

    // This aborts if the sender is not a voter.
    // 如果发送者不是投票者，则中止
    let index = vote.voters.find_index!(|voter| voter == ctx.sender()).extract();
    vote.votes[index].fill(encrypted_vote);
}

/// Seal批准函数
/// 检查投票是否已完成（所有投票者都已投票）
entry fun seal_approve(id: vector<u8>, vote: &Vote) {
    assert!(id == object::id(vote).to_bytes(), EInvalidVote);
    assert!(vote.votes.all!(|vote| vote.is_some()), EVoteNotDone);
}

/// Finalize a vote.
/// Updates the `result` field of the vote to hold the votes of the corresponding voters.
/// Aborts if the vote has already been finalized.
/// Aborts if there are not enough keys or if they are not valid, e.g. if they were derived for a different purpose.
/// In case the keys are valid but a vote, is invalid, decrypt will just set the corresponding result to none.
///
/// 最终确定投票
/// 更新投票的`result`字段以保存相应投票者的投票
/// 如果投票已经最终确定，则中止
/// 如果没有足够的密钥或密钥无效（例如，如果它们是为不同目的派生的），则中止
/// 如果密钥有效但投票无效，解密将只是将相应的结果设置为none
public fun finalize_vote(
    vote: &mut Vote,
    keys: &vector<VerifiedDerivedKey>,
    public_keys: &vector<PublicKey>,
) {
    assert!(vote.result.is_none(), EAlreadyFinalized);

    // This aborts if there are not enough keys or if they are invalid, e.g. if they were derived for a different purpose.
    // However, in case the keys are valid but some of the encrypted objects, aka the votes, are invalid, decrypt will just return none for these votes.
    // 如果没有足够的密钥或密钥无效（例如，如果它们是为不同目的派生的），则中止
    // 但是，如果密钥有效但某些加密对象（即投票）无效，解密将只为这些投票返回none
    vote.result.fill(vote.votes.map_ref!(|vote| {
        let decrypted = decrypt(vote.borrow(), keys, public_keys);
        if (decrypted.is_some()) {
            let v = decrypted.borrow();
            // We expect the vote to be a single byte.
            // 我们期望投票是单个字节
            if (v.length() == 1) {
                return option::some(v[0])
            }
        };
        option::none()
    }));
    // The encrypted votes can be deleted here if they are not needed anymore.
    // 如果不再需要加密投票，可以在此处删除
}

/// 投票测试
#[test]
fun test_vote() {
    use seal::bf_hmac_encryption::{verify_derived_keys, get_public_key};
    use seal::key_server::{register, destroy_cap, KeyServer};
    use std::string;
    use seal::bf_hmac_encryption::parse_encrypted_object;
    use sui::test_scenario::{Self, next_tx, ctx};
    use sui::bls12381::g1_from_bytes;

    let addr1 = @0xA;
    let mut scenario = test_scenario::begin(addr1);

    // Setup key servers.
    // 设置密钥服务器
    let pk0 =
        x"a6b8194ba6ffa1bf4c4e13ab1e56833f99f45f97874e77b845b361305ddaa741174febc307d3e07f7d4d5bb08c0adf3d11a5b8774c84006fb0ba7435f045f56a61905bc283049c2175984528e40a36e0096aabd401a67b1ccc442416c33b5df9";
    let cap0 = register(
        string::utf8(b"mysten0"),
        string::utf8(b"https://mysten-labs.com"),
        0,
        pk0,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);
    let s0: KeyServer = test_scenario::take_shared(&scenario);

    let pk1 =
        x"ac1c15fe6c5476ebc8b5bc432dcea06a30c87f89d21b89159ceab06afb84e0e7edefaadb896771ee281d25b6845aa3a20bda9324de39a9909c00f09b344b053da835dfde943c995576ec5e2fcf93221006bb2fcec8ef5096b4b88c36e1aa861c";
    let cap1 = register(
        string::utf8(b"mysten1"),
        string::utf8(b"https://mysten-labs.com"),
        0,
        pk1,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);
    let s1: KeyServer = test_scenario::take_shared(&scenario);

    let pk2 =
        x"a8750277f240eb4d94c159b2ec47c1c19396f6e33691fbf50514906b3e70c0454d9a79cf1f1f5562e4ddad9c4505bfb405a9901ac6ba2a51c24919d7599c74a5155f83606f80c1a302de9865deb4577911493dc1608754d67051f755cd44c391";
    let cap2 = register(
        string::utf8(b"mysten2"),
        string::utf8(b"https://mysten-labs.com"),
        0,
        pk2,
        ctx(&mut scenario),
    );
    next_tx(&mut scenario, addr1);
    let s2: KeyServer = test_scenario::take_shared(&scenario);

    // Anyone can create a vote.
    // 任何人都可以创建投票
    let mut vote = create_vote(
        vector[@0x1, @0x2],
        vector[s0.id().to_inner(), s1.id().to_inner(), s2.id().to_inner()],
        2,
        scenario.ctx(),
    );

    // cargo run --bin seal-cli encrypt-hmac --message 0x07 --aad 0x0000000000000000000000000000000000000000000000000000000000000001 --package-id 0x0 --id 0x381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --threshold 2 a6b8194ba6ffa1bf4c4e13ab1e56833f99f45f97874e77b845b361305ddaa741174febc307d3e07f7d4d5bb08c0adf3d11a5b8774c84006fb0ba7435f045f56a61905bc283049c2175984528e40a36e0096aabd401a67b1ccc442416c33b5df9 ac1c15fe6c5476ebc8b5bc432dcea06a30c87f89d21b89159ceab06afb84e0e7edefaadb896771ee281d25b6845aa3a20bda9324de39a9909c00f09b344b053da835dfde943c995576ec5e2fcf93221006bb2fcec8ef5096b4b88c36e1aa861c a8750277f240eb4d94c159b2ec47c1c19396f6e33691fbf50514906b3e70c0454d9a79cf1f1f5562e4ddad9c4505bfb405a9901ac6ba2a51c24919d7599c74a5155f83606f80c1a302de9865deb4577911493dc1608754d67051f755cd44c391 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97
    // cargo run --bin seal-cli encrypt-hmac --message 0x2a --aad 0x0000000000000000000000000000000000000000000000000000000000000002 --package-id 0x0 --id 0x381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409 --threshold 2 a6b8194ba6ffa1bf4c4e13ab1e56833f99f45f97874e77b845b361305ddaa741174febc307d3e07f7d4d5bb08c0adf3d11a5b8774c84006fb0ba7435f045f56a61905bc283049c2175984528e40a36e0096aabd401a67b1ccc442416c33b5df9 ac1c15fe6c5476ebc8b5bc432dcea06a30c87f89d21b89159ceab06afb84e0e7edefaadb896771ee281d25b6845aa3a20bda9324de39a9909c00f09b344b053da835dfde943c995576ec5e2fcf93221006bb2fcec8ef5096b4b88c36e1aa861c a8750277f240eb4d94c159b2ec47c1c19396f6e33691fbf50514906b3e70c0454d9a79cf1f1f5562e4ddad9c4505bfb405a9901ac6ba2a51c24919d7599c74a5155f83606f80c1a302de9865deb4577911493dc1608754d67051f755cd44c391 -- 0x34401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab96 0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3 0xdba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a97

    // Cast votes. These have been encrypted using the Seal CLI.
    // 投票。这些已使用Seal CLI加密
    scenario.next_tx(@0x1);
    let encrypted_vote_1 = parse_encrypted_object(
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a970302008c6f6076588183b0d410931be8bf1bb007391782ae2fcd2c06a4a88693bc6af2f6297cf000694263c368b8a7daeb902014310e3745c7f72f7f06c35e9c061ccea6d98ee36e6398667eccee117d51734f0d9c661c678256439a1d7f8742099776038d1de9d7256d3d7b7217bcec4604f955d307dd7b2e3a0f7c81dd8a1d4cf2dcdabf69977d502d1a217a6f660ecbaf175544452edea382edfa207cb8d4fb82154505fbbaeb49d2c38d34bba2019a95c2570b0cb212a1c623c807610f683a33c8487b7557dfadfbca6a070be75f85fbf9636b04344d6c7132b51e21a19a94dd722a01013d0120000000000000000000000000000000000000000000000000000000000000000134b63b8a1f1ec075ed713961c1307916d6f91e175f681792ddca855109649fd6",
    );
    cast_vote(&mut vote, encrypted_vote_1, scenario.ctx());

    scenario.next_tx(@0x2);
    let encrypted_vote_2 = parse_encrypted_object(
        x"00000000000000000000000000000000000000000000000000000000000000000020381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f40903034401905bebdf8c04f3cd5f04f442a39372c8dc321c29edfb4f9cb30b23ab9601d726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d302dba72804cc9504a82bbaa13ed4a83a0e2c6219d7e45125cf57fd10cbab957a9703020097e7aeaa9de3d676ff16624deca8a1145cb5a2aa18953c4bd863aea14224696fe5ac361920996bf112e18bb8e33c2314136b2f5b48ba54c72caa588ecd32b650abde099fcc8ed53bcaae96f4206098e4415ecf37c17eda295646367273fe3125032178fd1f17141060ae3477b05ac03193bcc41409ec704a86aee28d01dd8a5e0f40deb91e761aa090a2ec163de66b849decd4be59c93ece314884712601ad16e1274453d3c5a987c9db650ce12893ac0a24dc3c59fd65dd41ebf3a566731ff99cebf9d2a9d8129fe832ec17aa63c2e36f18b24243efcd7ddd5ab0e233c10ef92101014f0120000000000000000000000000000000000000000000000000000000000000000284e242463c417d466724379508687f52a5cf7cd64aaf9953904613ecba4d2ef7",
    );
    cast_vote(&mut vote, encrypted_vote_2, scenario.ctx());

    // Both voters have now voted, so the vote is sealed and seal_approve will succeed.
    // 两位投票者现在都已投票，所以投票已封存，seal_approve将成功
    seal_approve(vote.id(), &vote);

    // The derived keys. These should have been retrieved from key servers
    // 派生密钥。这些应该已从密钥服务器检索
    let dk0 = g1_from_bytes(
        &x"8288e333ba467097dceae2c9bb208712de3f5c6e77cbf7a4b57e3c4a9156a0576949e717cd0ebf46347516ffa424af03",
    );
    let dk1 = g1_from_bytes(
        &x"b307ab62d32189223cef111a150c35d87f037830e39cfcf78583737361ec329b321e1ae3e17a20482a1e6ef388109033",
    );

    // Verify the derived keys
    // 验证派生密钥
    let user_secret_keys = vector[dk0, dk1];
    let vdks = verify_derived_keys(
        &user_secret_keys,
        @0x0,
        x"381dd9078c322a4663c392761a0211b527c127b29583851217f948d62131f409",
        &vector[get_public_key(&s0), get_public_key(&s1)],
    );

    // Finalize vote
    // 最终确定投票
    assert!(vote.result.is_none());
    finalize_vote(
        &mut vote,
        &vdks,
        &vector[get_public_key(&s0), get_public_key(&s1), get_public_key(&s2)],
    );
    assert!(vote.result.is_some());

    // Voter 1 voted '7' and voter 2 voted '42'.
    // 投票者1投票为'7'，投票者2投票为'42'
    assert!(vote.result.borrow()[0].borrow() == 7);
    assert!(vote.result.borrow()[1].borrow() == 42);

    // Clean up
    // 清理
    test_scenario::return_shared(s0);
    test_scenario::return_shared(s1);
    test_scenario::return_shared(s2);
    destroy_for_testing(vote);
    destroy_cap(cap0);
    destroy_cap(cap1);
    destroy_cap(cap2);
    test_scenario::end(scenario);
}
