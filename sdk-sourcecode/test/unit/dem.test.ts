// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * DEM（数据加密机制）测试文件
 * 测试AES-GCM和HMAC-CTR加密算法的正确性
 */

import { fromHex } from '@mysten/bcs';
import { describe, expect, it } from 'vitest';

import { AesGcm256, Hmac256Ctr } from '../../src/dem.js';

// 测试消息，用于加密和解密测试
const testMessage = new TextEncoder().encode(
	'On the guards‘ platform at Elsinore, Horatio waits with Barnardo and Marcellus to question a ghost that has twice before appeared.',
);
// 测试用附加认证数据(AAD)
const testAad = new Uint8Array([1, 2, 3, 4]);

describe('AES encryption', () => {
	describe('AesGcm256', () => {
		/**
		 * 测试AES-GCM-256加密和解密的基本功能
		 * 确保加密后能够正确解密回原始消息
		 */
		it('should encrypt and decrypt successfully', async () => {
			const aes = new AesGcm256(testMessage, testAad);
			const key = await aes.generateKey();
			expect(key.length).toBe(32); // 密钥应为32字节(256位)

			const ciphertext = await aes.encrypt(key);
			if (!('Aes256Gcm' in ciphertext)) {
				throw new Error('Invalid ciphertext');
			}
			const aadArray = ciphertext.Aes256Gcm.aad ?? [];
			expect(new Uint8Array(aadArray)).toEqual(testAad); // 验证AAD正确存储和恢复

			// 验证tag是16字节，总长度为tag+消息长度
			expect(ciphertext.Aes256Gcm?.blob.length).toBe(16 + testMessage.length);

			const decrypted = await AesGcm256.decrypt(key, ciphertext);
			expect(decrypted).toEqual(testMessage); // 验证解密结果与原始消息相同
		});

		/**
		 * 测试使用错误密钥解密时应失败
		 * 验证加密系统的安全性
		 */
		it('should fail decryption with wrong key', async () => {
			const aes = new AesGcm256(testMessage, testAad);
			const key = await aes.generateKey();
			const wrongKey = await aes.generateKey();
			const ciphertext = await aes.encrypt(key);

			await expect(AesGcm256.decrypt(wrongKey, ciphertext)).rejects.toThrow();
		});

		/**
		 * 测试使用错误的AAD解密时应失败
		 * 验证认证数据的完整性检查
		 */
		it('should fail decryption with wrong AAD', async () => {
			const aes = new AesGcm256(testMessage, testAad);
			const key = await aes.generateKey();
			let ciphertext = await aes.encrypt(key);
			if (!('Aes256Gcm' in ciphertext)) {
				throw new Error('Invalid ciphertext');
			}
			ciphertext.Aes256Gcm.aad = new Uint8Array([1]); // 修改AAD

			await expect(AesGcm256.decrypt(key, ciphertext)).rejects.toThrow();
		});

		/**
		 * 测试空AAD的处理
		 * 确保即使没有AAD也能正常工作
		 */
		it('should handle empty AAD', async () => {
			const emptyAad = new Uint8Array();
			const aes = new AesGcm256(testMessage, emptyAad);
			const key = await aes.generateKey();

			const ciphertext = await aes.encrypt(key);
			const decrypted = await AesGcm256.decrypt(key, ciphertext);

			expect(decrypted).toEqual(testMessage);
		});

		/**
		 * 测试空消息的处理
		 * 确保能够加密和解密空消息
		 */
		it('should handle empty message', async () => {
			const emptyMessage = new Uint8Array();
			const aes = new AesGcm256(emptyMessage, testAad);
			const key = await aes.generateKey();

			const ciphertext = await aes.encrypt(key);
			const decrypted = await AesGcm256.decrypt(key, ciphertext);

			expect(decrypted).toEqual(emptyMessage);
		});
	});
});

describe('Hmac256Ctr', () => {
	/**
	 * 测试HMAC-SHA256-CTR加密和解密的基本功能
	 * 确保加密后能够正确解密回原始消息
	 */
	it('should encrypt and decrypt successfully', async () => {
		const hmac = new Hmac256Ctr(testMessage, testAad);
		const key = await hmac.generateKey();
		expect(key.length).toBe(32); // 密钥应为32字节(256位)

		const ciphertext = await hmac.encrypt(key);
		const decrypted = await Hmac256Ctr.decrypt(key, ciphertext);

		expect(decrypted).toEqual(testMessage); // 验证解密结果与原始消息相同
	});

	/**
	 * 使用已知数据进行测试
	 * 验证实现与标准测试向量的一致性
	 */
	it('test vector', async () => {
		const plaintext = new TextEncoder().encode(
			'The difference between a Miracle and a Fact is exactly the difference between a mermaid and a seal.',
		);
		const aad = new TextEncoder().encode('Mark Twain');
		const key = fromHex('5bfdfd7c814903f1311bebacfffa3c001cbeb1cbb3275baa9aafe21fadd9f396');
		const blob = fromHex(
			'b0c4eee6fbd97a2fb86bbd1e0dafa47d2ce5c9e8975a50c2d9eae02ebede8fee6b6434e68584be475b89089fce4c451cbd4c0d6e00dbcae1241abaf237df2eccdd86b890d35e4e8ae9418386012891d8413483d64179ce1d7fe69ad25d546495df54a1',
		);
		const mac = fromHex('5de3ffdd9d7a258e651ebdba7d80839df2e19ea40cd35b6e1b06375181a0c2f2');

		// 构造预期的密文对象
		const c = {
			Hmac256Ctr: {
				blob,
				mac,
				aad,
			},
		};

		// 验证解密功能
		expect(await Hmac256Ctr.decrypt(key, c)).toEqual(plaintext);
		// 验证加密功能产生预期的密文
		await expect(new Hmac256Ctr(plaintext, aad).encrypt(key)).resolves.toEqual(c);
	});
});
