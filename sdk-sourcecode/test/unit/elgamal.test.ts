// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * ElGamal加密测试文件
 * 测试椭圆曲线ElGamal加密系统的功能正确性
 */

import { describe, expect, it } from 'vitest';

import { G1Element, Scalar } from '../../src/bls12381';
import { elgamalDecrypt, generateSecretKey, toPublicKey } from '../../src/elgamal';

describe('ElGamal encryption', () => {
	/**
	 * 测试密钥对生成功能
	 * 验证生成的密钥对格式和大小是否正确
	 */
	it('should generate valid key pair', () => {
		const sk = generateSecretKey();
		const pk = toPublicKey(sk);

		expect(sk).toBeInstanceOf(Uint8Array);
		expect(sk.length).toBe(32); // 私钥应为32字节(256位)
		expect(pk).toBeInstanceOf(Uint8Array);
		expect(pk.length).toBe(48); // 公钥应为48字节(G1元素)
	});

	/**
	 * 测试加密和解密功能
	 * 验证使用正确私钥解密能恢复原始消息，而错误私钥则不能
	 */
	it('should decrypt successfully', () => {
		// 生成密钥对
		const sk = generateSecretKey();
		const pk = toPublicKey(sk);

		// 创建随机消息
		const message = G1Element.generator().multiply(Scalar.random());
		const messageBytes = message.toBytes();

		// 执行ElGamal加密
		const r = Scalar.random(); // 随机因子
		const c1 = G1Element.generator().multiply(r); // 第一个密文元素
		const c2 = G1Element.fromBytes(pk).multiply(r).add(message); // 第二个密文元素
		const ciphertext: [Uint8Array, Uint8Array] = [c1.toBytes(), c2.toBytes()];

		// 使用正确的私钥解密
		const decrypted = elgamalDecrypt(sk, ciphertext);
		expect(decrypted).toEqual(messageBytes); // 验证解密结果与原始消息相同

		// 使用不同的私钥解密，应该得到不同的结果
		const sk2 = generateSecretKey();
		const decrypted2 = elgamalDecrypt(sk2, ciphertext);
		expect(decrypted2).not.toEqual(message.toBytes()); // 确保使用错误密钥解密得到不同结果
	});

	/**
	 * 测试无效密文的处理
	 * 验证系统能够正确检测和拒绝格式无效的密文
	 */
	it('should throw on invalid ciphertext', () => {
		const sk = generateSecretKey();

		// 测试G1点长度错误的密文
		const invalidCiphertext1: [Uint8Array, Uint8Array] = [
			new Uint8Array(47), // G1点错误长度(应为48字节)
			new Uint8Array(48),
		];

		const invalidCiphertext2: [Uint8Array, Uint8Array] = [
			new Uint8Array(48),
			new Uint8Array(47), // G1点错误长度(应为48字节)
		];

		// 验证解密函数正确拒绝无效密文
		expect(() => elgamalDecrypt(sk, invalidCiphertext1)).toThrow();
		expect(() => elgamalDecrypt(sk, invalidCiphertext2)).toThrow();
	});
});
