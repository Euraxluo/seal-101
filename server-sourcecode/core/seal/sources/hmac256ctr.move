// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * HMAC-SHA3-256 CTR模式对称加密实现
 * 
 * 本模块实现了基于HMAC-SHA3-256的CTR（计数器）模式对称加密和解密功能。
 * 这种模式结合了CTR的流加密特性和HMAC的消息认证能力，提供了同时保证
 * 机密性和完整性的加密方案。
 * 
 * 主要特点:
 * - 使用HMAC-SHA3-256生成密钥流
 * - 支持任意长度消息的加密
 * - 包含消息认证码(MAC)验证
 * - 支持附加认证数据(AAD)
 */
module seal::hmac256ctr;

use std::{bcs, option::{none, some}};
use sui::hmac::hmac_sha3_256;

/// Decrypt a message that was encrypted in Hmac256Ctr mode.
public(package) fun decrypt(
    ciphertext: &vector<u8>,
    mac: &vector<u8>,
    aad: &vector<u8>,
    key: &vector<u8>,
): Option<vector<u8>> {
    if (mac(key, aad, ciphertext) != mac) {
        return none()
    };

    let encryption_key = hmac_sha3_256(key, &vector[1]);

    let mut next_block = 0;
    let mut i = 0;
    let mut current_mask = vector[];
    some(ciphertext.map_ref!(|b| {
        if (i == 0) {
            current_mask = hmac_sha3_256(&encryption_key, &bcs::to_bytes(&(next_block as u64)));
            next_block = next_block + 1;
        };
        let result = *b ^ current_mask[i];
        i = (i + 1) % 32;
        result
    }))
}

/**
 * 计算消息认证码(MAC)
 * 
 * 使用HMAC-SHA3-256计算密文和AAD的MAC，用于验证数据完整性和真实性。
 * MAC计算格式为：HMAC(mac_key, len(AAD) || AAD || ciphertext)
 */
fun mac(key: &vector<u8>, aux: &vector<u8>, ciphertext: &vector<u8>): vector<u8> {
    let mut mac_input: vector<u8> = bcs::to_bytes(&aux.length());
    mac_input.append(*aux);
    mac_input.append(*ciphertext);

    let mac_key = hmac_sha3_256(key, &vector[2]);
    hmac_sha3_256(&mac_key, &mac_input)
}

/**
 * 短消息解密测试
 * 
 * 使用预定义的密钥、密文和MAC验证解密功能
 */
#[test]
fun test_decrypt() {
    let key = x"4804597e77d5025ab89d8559fe826dbd5591aaa5a0a3ca19ea572350e2a08c6b";
    let ciphertext = x"98bf8da0ccbb35b6cf41effc83";
    let mac = x"6c3d7fdb9b3a16a552b43a3300d6493f328e97aebf0697645cd35348ac926ec2";
    let aux = b"something";
    let decrypted = decrypt(&ciphertext, &mac, &aux, &key).borrow();
    assert!(decrypted == b"Hello, world!");
}

/**
 * MAC验证失败测试
 * 
 * 验证当AAD不匹配时解密应该失败
 */
#[test]
fun test_decrypt_fail() {
    let key = x"4804597e77d5025ab89d8559fe826dbd5591aaa5a0a3ca19ea572350e2a08c6b";
    let ciphertext = x"98bf8da0ccbb35b6cf41effc83";
    let mac = x"6c3d7fdb9b3a16a552b43a3300d6493f328e97aebf0697645cd35348ac926ec2";
    let aux = b"something else";
    assert!(decrypt(&ciphertext, &mac, &aux, &key) == none());
}

/**
 * 长消息解密测试
 * 
 * 测试解密较长消息的功能，验证CTR模式对任意长度消息的支持
 */
#[test]
fun test_decrypt_long() {
    let key = x"f44a2fa43047d60b0d306dd26da1ef64647d4903850d88e61f3fff1f856c3ae3";
    let ciphertext =
        x"3c0c31923589a18cb38c34802aa28de8831756c4c6f4043afa7e12c7e3dcd8f4798e7679983201f0d99f03a6f7c6c63752a8ac0deb0d1588120ae03e320238cb2ba4b458e336b7f70ad38ac23b5c149523a74817fb82bd4061fe101275638730239411";
    let mac = x"a26c79314ebe7c043506f779d669ce24fbff50f543f0074243d53aa5b661504a";
    let aux = b"Mark Twain";
    let decrypted = decrypt(&ciphertext, &mac, &aux, &key).borrow();
    assert!(
        decrypted == b"The difference between a Miracle and a Fact is exactly the difference between a mermaid and a seal.",
    );
}
