// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 密封(Seal)加密测试文件
 * 测试基于身份的加密(IBE)和数据加密机制(DEM)的组合使用
 * 验证加密和解密操作的正确性
 */

import { fromHex, toHex } from '@mysten/bcs';
import { describe, expect, it } from 'vitest';

import { EncryptedObject } from '../../src/bcs';
import { G1Element, G2Element, Scalar } from '../../src/bls12381';
import { decrypt } from '../../src/decrypt';
import { AesGcm256, Hmac256Ctr, Plain } from '../../src/dem';
import { encrypt, KemType } from '../../src/encrypt';
import { BonehFranklinBLS12381Services, DST } from '../../src/ibe';
import { kdf } from '../../src/kdf';
import { KeyCacheKey } from '../../src/types';
import { createFullId } from '../../src/utils';

describe('Seal encryption tests', () => {
	/**
	 * 生成密钥对函数
	 * 创建随机的标量私钥和对应的G2元素公钥
	 * 
	 * @returns [私钥, 公钥] 密钥对
	 */
	function generateKeyPair(): [Scalar, G2Element] {
		const sk = Scalar.random();
		const pk = G2Element.generator().multiply(sk);
		return [sk, pk];
	}

	/**
	 * 提取用户私钥函数
	 * 模拟密钥服务器为用户ID生成私钥的过程
	 * 
	 * @param sk - 主私钥
	 * @param id - 用户身份
	 * @returns 用户的私钥(G1元素)
	 */
	function extractUserSecretKey(sk: Scalar, id: Uint8Array): G1Element {
		return G1Element.hashToCurve(id, DST).multiply(sk);
	}

	/**
	 * 测试基本的加密和解密流程
	 * 验证完整的加密-解密周期能正确恢复原始数据
	 */
	it('simple encrypt+decrypt (Aes256Gcm/BonehFranklinBLS12381DemCCA)', async () => {
		// 生成测试数据
		const data = new TextEncoder().encode('hello world');
		const aad = new TextEncoder().encode('aad');
		const kemType = KemType.BonehFranklinBLS12381DemCCA;

		// 设置密钥服务器
		const [sk1, pk1] = generateKeyPair();
		const keyServers = [
			{
				objectId: '0x01',
				name: 'server1',
				url: 'http://localhost:8000',
				keyType: 0,
				pk: pk1.toBytes(),
			},
		];

		// 创建加密输入
		const encryptionInput = new AesGcm256(data, aad);
		
		// 执行加密
		const packageId = '0x1234';
		const id = '0x5678';
		const threshold = 1;
		const obj = await encrypt({
			keyServers,
			kemType,
			threshold,
			packageId,
			id,
			encryptionInput,
		});

		// 解析加密对象
		const encrypted = EncryptedObject.parse(obj.encryptedObject);
		
		// 提取用户私钥
		const fullId = createFullId(DST, packageId, id);
		// 在实际系统中，这部分通常由密钥服务器执行
		const userSecretKey = extractUserSecretKey(sk1, fromHex(fullId));
		
		// 准备解密密钥缓存
		const keys = new Map<KeyCacheKey, G1Element>();
		keys.set(`${fullId}:${keyServers[0].objectId}`, userSecretKey);
		
		// 执行解密
		const decrypted = await decrypt({
			encryptedObject: encrypted,
			keys,
		});

		// 验证解密结果与原始数据相同
		expect(decrypted).toEqual(data);
	});

	/**
	 * 测试多服务器情况下的加密和解密
	 * 验证阈值加密方案的正确性
	 */
	it('encrypt+decrypt with multiple servers and threshold', async () => {
		// 生成测试数据
		const data = new TextEncoder().encode('hello world');
		const aad = new TextEncoder().encode('aad');
		const kemType = KemType.BonehFranklinBLS12381DemCCA;

		// 设置3个密钥服务器
		const [sk1, pk1] = generateKeyPair();
		const [sk2, pk2] = generateKeyPair();
		const [sk3, pk3] = generateKeyPair();
		const keyServers = [
			{
				objectId: '0x01',
				name: 'server1',
				url: 'http://localhost:8000',
				keyType: 0,
				pk: pk1.toBytes(),
			},
			{
				objectId: '0x02',
				name: 'server2',
				url: 'http://localhost:8001',
				keyType: 0,
				pk: pk2.toBytes(),
			},
			{
				objectId: '0x03',
				name: 'server3',
				url: 'http://localhost:8002',
				keyType: 0,
				pk: pk3.toBytes(),
			},
		];

		// 阈值设为2，表示需要至少2个服务器的密钥才能解密
		const threshold = 2;
		// 创建加密输入
		const encryptionInput = new AesGcm256(data, aad);
		
		// 执行加密
		const packageId = '0x1234';
		const id = '0x5678';
		const obj = await encrypt({
			keyServers,
			kemType,
			threshold,
			packageId,
			id,
			encryptionInput,
		});

		// 解析加密对象
		const encrypted = EncryptedObject.parse(obj.encryptedObject);
		
		// 提取用户私钥
		const fullId = createFullId(DST, packageId, id);
		const userSecretKey1 = extractUserSecretKey(sk1, fromHex(fullId));
		const userSecretKey2 = extractUserSecretKey(sk2, fromHex(fullId));
		
		// 准备解密密钥缓存（只用前两个服务器的密钥）
		const keys = new Map<KeyCacheKey, G1Element>();
		keys.set(`${fullId}:${keyServers[0].objectId}`, userSecretKey1);
		keys.set(`${fullId}:${keyServers[1].objectId}`, userSecretKey2);
		
		// 执行解密
		const decrypted = await decrypt({
			encryptedObject: encrypted,
			keys,
		});

		// 验证解密结果与原始数据相同
		expect(decrypted).toEqual(data);
	});

	/**
	 * 测试使用Plain密文类型
	 * Plain只是简单包装密钥，不进行实际加密
	 */
	it('encrypts with Plain ciphertext type', async () => {
		// 设置密钥服务器
		const [sk1, pk1] = generateKeyPair();
		const keyServers = [
			{
				objectId: '0x01',
				name: 'server1',
				url: 'http://localhost:8000',
				keyType: 0,
				pk: pk1.toBytes(),
			},
		];

		// 使用Plain加密输入
		const encryptionInput = new Plain();
		
		// 执行加密
		const packageId = '0x1234';
		const id = '0x5678';
		const threshold = 1;
		const obj = await encrypt({
			keyServers,
			kemType: KemType.BonehFranklinBLS12381DemCCA,
			threshold,
			packageId,
			id,
			encryptionInput,
		});

		// 解析加密对象
		const encrypted = EncryptedObject.parse(obj.encryptedObject);
		
		// 验证加密对象中包含Plain类型
		expect(encrypted.ciphertext.Plain).toBeDefined();
		
		// 提取用户私钥
		const fullId = createFullId(DST, packageId, id);
		const userSecretKey = extractUserSecretKey(sk1, fromHex(fullId));
		
		// 准备解密密钥缓存
		const keys = new Map<KeyCacheKey, G1Element>();
		keys.set(`${fullId}:${keyServers[0].objectId}`, userSecretKey);
		
		// 执行解密
		const decrypted = await decrypt({
			encryptedObject: encrypted,
			keys,
		});

		// 验证解密结果为正确的密钥
		expect(decrypted).toEqual(obj.key);
	});

	/**
	 * 测试HMAC-CTR加密模式
	 * 验证使用HMAC-CTR进行加密和解密的正确性
	 */
	it('encrypts with HMAC-CTR type', async () => {
		// 生成测试数据
		const data = new TextEncoder().encode('hello world');
		const aad = new TextEncoder().encode('aad');
		
		// 设置密钥服务器
		const [sk1, pk1] = generateKeyPair();
		const keyServers = [
			{
				objectId: '0x01',
				name: 'server1',
				url: 'http://localhost:8000',
				keyType: 0,
				pk: pk1.toBytes(),
			},
		];

		// 使用HMAC-CTR加密输入
		const encryptionInput = new Hmac256Ctr(data, aad);
		
		// 执行加密
		const packageId = '0x1234';
		const id = '0x5678';
		const threshold = 1;
		const obj = await encrypt({
			keyServers,
			kemType: KemType.BonehFranklinBLS12381DemCCA,
			threshold,
			packageId,
			id,
			encryptionInput,
		});

		// 解析加密对象
		const encrypted = EncryptedObject.parse(obj.encryptedObject);
		
		// 验证加密对象中包含Hmac256Ctr类型
		expect(encrypted.ciphertext.Hmac256Ctr).toBeDefined();
		
		// 提取用户私钥
		const fullId = createFullId(DST, packageId, id);
		const userSecretKey = extractUserSecretKey(sk1, fromHex(fullId));
		
		// 准备解密密钥缓存
		const keys = new Map<KeyCacheKey, G1Element>();
		keys.set(`${fullId}:${keyServers[0].objectId}`, userSecretKey);
		
		// 执行解密
		const decrypted = await decrypt({
			encryptedObject: encrypted,
			keys,
		});

		// 验证解密结果与原始数据相同
		expect(decrypted).toEqual(data);
	});

	it('sanity checks for encryption format', async () => {
		const [, pk1] = generateKeyPair();
		const [, pk2] = generateKeyPair();
		const [, pk3] = generateKeyPair();

		const msg = new TextEncoder().encode('My super secret message');
		const aad = new Uint8Array([1, 2, 3, 4]);

		const { encryptedObject } = await encrypt({
			keyServers: [
				{
					objectId: '0x0000000000000000000000000000000000000000000000000000000000000001',
					pk: pk1.toBytes(),
					name: 'test',
					url: 'https://test.com',
					keyType: 0,
				},
				{
					objectId: '0x0000000000000000000000000000000000000000000000000000000000000002',
					pk: pk2.toBytes(),
					name: 'test2',
					url: 'https://test2.com',
					keyType: 0,
				},
				{
					objectId: '0x0000000000000000000000000000000000000000000000000000000000000003',
					pk: pk3.toBytes(),
					name: 'test3',
					url: 'https://test3.com',
					keyType: 0,
				},
			],
			kemType: KemType.BonehFranklinBLS12381DemCCA,
			threshold: 2,
			packageId: '0x0000000000000000000000000000000000000000000000000000000000000000',
			id: toHex(new Uint8Array([1, 2, 3, 4])),
			encryptionInput: new AesGcm256(msg, aad),
		});
		const parsed = EncryptedObject.parse(encryptedObject);

		expect(parsed.version).toEqual(0);
		expect(parsed.id).toEqual(toHex(new Uint8Array([1, 2, 3, 4])));
		expect(parsed.packageId).toEqual(
			'0x0000000000000000000000000000000000000000000000000000000000000000',
		);
		expect(parsed.services.length).toEqual(3);
		expect(parsed.threshold).toEqual(2);
	});

	it('test encryption round-trip with AesGcm-mode', async () => {
		const [sk1, pk1] = generateKeyPair();
		const [sk2, pk2] = generateKeyPair();
		const [sk3, pk3] = generateKeyPair();

		const msg = new TextEncoder().encode('My super secret message');
		const aad = new Uint8Array([1, 2, 3, 4]);

		const objectId1 = '0x0000000000000000000000000000000000000000000000000000000000000001';
		const objectId2 = '0x0000000000000000000000000000000000000000000000000000000000000002';
		const objectId3 = '0x0000000000000000000000000000000000000000000000000000000000000003';

		const { encryptedObject } = await encrypt({
			keyServers: [
				{
					objectId: objectId1,
					pk: pk1.toBytes(),
					name: 'test',
					url: 'https://test.com',
					keyType: 0,
				},
				{
					objectId: objectId2,
					pk: pk2.toBytes(),
					name: 'test2',
					url: 'https://test2.com',
					keyType: 0,
				},
				{
					objectId: objectId3,
					pk: pk3.toBytes(),
					name: 'test3',
					url: 'https://test3.com',
					keyType: 0,
				},
			],
			kemType: KemType.BonehFranklinBLS12381DemCCA,
			threshold: 2,
			packageId: '0x0000000000000000000000000000000000000000000000000000000000000000',
			id: '01020304',
			encryptionInput: new AesGcm256(msg, aad),
		});

		const parsed = EncryptedObject.parse(encryptedObject);

		const id = createFullId(DST, parsed.packageId, parsed.id);
		const idBytes = fromHex(id);

		const usk1 = extractUserSecretKey(sk1, idBytes);
		const usk2 = extractUserSecretKey(sk2, idBytes);
		const usk3 = extractUserSecretKey(sk3, idBytes);

		// Sanity checks for verify_user_secret_key
		expect(BonehFranklinBLS12381Services.verifyUserSecretKey(usk1, id, pk1)).toBeTruthy();
		expect(BonehFranklinBLS12381Services.verifyUserSecretKey(usk2, id, pk2)).toBeTruthy();
		expect(BonehFranklinBLS12381Services.verifyUserSecretKey(usk3, id, pk3)).toBeTruthy();
		expect(
			BonehFranklinBLS12381Services.verifyUserSecretKey(usk1, toHex(new Uint8Array([1, 2])), pk1),
		).toBeFalsy();
		expect(
			BonehFranklinBLS12381Services.verifyUserSecretKey(G1Element.generator(), id, pk1),
		).toBeFalsy();
		expect(
			BonehFranklinBLS12381Services.verifyUserSecretKey(usk1, id, G2Element.generator()),
		).toBeFalsy();

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([
					[`${id}:${objectId1}`, usk1],
					[`${id}:${objectId2}`, usk2],
					[`${id}:${objectId3}`, usk3],
				]),
			}),
		).resolves.toEqual(msg);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([
					[`${id}:${objectId2}`, usk2],
					[`${id}:${objectId3}`, usk3],
				]),
			}),
		).resolves.toEqual(msg);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([[`${id}:${objectId1}`, usk1]]),
			}),
		).rejects.toThrow();
	});

	it('test encryption round-trip with Hmac256Ctr-mode', async () => {
		const [sk1, pk1] = generateKeyPair();
		const [sk2, pk2] = generateKeyPair();
		const [sk3, pk3] = generateKeyPair();

		const msg = new TextEncoder().encode('My super secret message');
		const aad = new Uint8Array([1, 2, 3, 4]);

		const objectId1 = '0x0000000000000000000000000000000000000000000000000000000000000001';
		const objectId2 = '0x0000000000000000000000000000000000000000000000000000000000000002';
		const objectId3 = '0x0000000000000000000000000000000000000000000000000000000000000003';

		const { encryptedObject } = await encrypt({
			keyServers: [
				{
					objectId: objectId1,
					pk: pk1.toBytes(),
					name: 'test',
					url: 'https://test.com',
					keyType: 0,
				},
				{
					objectId: objectId2,
					pk: pk2.toBytes(),
					name: 'test2',
					url: 'https://test2.com',
					keyType: 0,
				},
				{
					objectId: objectId3,
					pk: pk3.toBytes(),
					name: 'test3',
					url: 'https://test3.com',
					keyType: 0,
				},
			],
			kemType: KemType.BonehFranklinBLS12381DemCCA,
			threshold: 2,
			packageId: '0x0000000000000000000000000000000000000000000000000000000000000000',
			id: '01020304',
			encryptionInput: new Hmac256Ctr(msg, aad),
		});

		const parsed = EncryptedObject.parse(encryptedObject);

		const id = createFullId(DST, parsed.packageId, parsed.id);
		const idBytes = fromHex(id);

		const usk1 = extractUserSecretKey(sk1, idBytes);
		const usk2 = extractUserSecretKey(sk2, idBytes);
		const usk3 = extractUserSecretKey(sk3, idBytes);

		// Sanity checks for verify_user_secret_key
		expect(BonehFranklinBLS12381Services.verifyUserSecretKey(usk1, id, pk1)).toBeTruthy();
		expect(BonehFranklinBLS12381Services.verifyUserSecretKey(usk2, id, pk2)).toBeTruthy();
		expect(BonehFranklinBLS12381Services.verifyUserSecretKey(usk3, id, pk3)).toBeTruthy();
		expect(
			BonehFranklinBLS12381Services.verifyUserSecretKey(usk1, toHex(new Uint8Array([1, 2])), pk1),
		).toBeFalsy();
		expect(
			BonehFranklinBLS12381Services.verifyUserSecretKey(G1Element.generator(), id, pk1),
		).toBeFalsy();
		expect(
			BonehFranklinBLS12381Services.verifyUserSecretKey(usk1, id, G2Element.generator()),
		).toBeFalsy();

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([
					[`${id}:${objectId1}`, usk1],
					[`${id}:${objectId2}`, usk2],
					[`${id}:${objectId3}`, usk3],
				]),
			}),
		).resolves.toEqual(msg);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([
					[`${id}:${objectId2}`, usk2],
					[`${id}:${objectId3}`, usk3],
				]),
			}),
		).resolves.toEqual(msg);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([[`${id}:${objectId1}`, usk1]]),
			}),
		).rejects.toThrow();
	});

	it('test encryption round-trip with Plain-mode', async () => {
		const [sk1, pk1] = generateKeyPair();
		const [sk2, pk2] = generateKeyPair();
		const [sk3, pk3] = generateKeyPair();

		const objectId1 = '0x0000000000000000000000000000000000000000000000000000000000000001';
		const objectId2 = '0x0000000000000000000000000000000000000000000000000000000000000002';
		const objectId3 = '0x0000000000000000000000000000000000000000000000000000000000000003';

		const { encryptedObject, key } = await encrypt({
			keyServers: [
				{
					objectId: objectId1,
					pk: pk1.toBytes(),
					name: 'test',
					url: 'https://test.com',
					keyType: 0,
				},
				{
					objectId: objectId2,
					pk: pk2.toBytes(),
					name: 'test2',
					url: 'https://test2.com',
					keyType: 0,
				},
				{
					objectId: objectId3,
					pk: pk3.toBytes(),
					name: 'test3',
					url: 'https://test3.com',
					keyType: 0,
				},
			],
			kemType: KemType.BonehFranklinBLS12381DemCCA,
			threshold: 2,
			packageId: '0x0000000000000000000000000000000000000000000000000000000000000000',
			id: '01020304',
			encryptionInput: new Plain(),
		});

		const parsed = EncryptedObject.parse(encryptedObject);

		const id = createFullId(DST, parsed.packageId, parsed.id);
		const idBytes = fromHex(id);

		const usk1 = extractUserSecretKey(sk1, idBytes);
		const usk2 = extractUserSecretKey(sk2, idBytes);
		const usk3 = extractUserSecretKey(sk3, idBytes);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([
					[`${id}:${objectId1}`, usk1],
					[`${id}:${objectId2}`, usk2],
					[`${id}:${objectId3}`, usk3],
				]),
			}),
		).resolves.toEqual(key);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([
					[`${id}:${objectId2}`, usk2],
					[`${id}:${objectId3}`, usk3],
				]),
			}),
		).resolves.toEqual(key);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([[`${id}:${objectId1}`, usk1]]),
			}),
		).rejects.toThrow();
	});

	it('G1 hash-to-curve regression test', async () => {
		const packageId = toHex(new Uint8Array(32));
		const innerId = toHex(new Uint8Array([1, 2, 3, 4]));
		const hash = G1Element.hashToCurve(fromHex(createFullId(DST, packageId, innerId)));
		const expected =
			'b32685b6ffd1f373faf3abb10c05772e033f75da8af729c3611d81aea845670db48ceadd0132d3a667dbbaa36acefac7';
		expect(toHex(hash.toBytes())).toEqual(expected);
	});

	it('kdf regression test', () => {
		const x = G1Element.generator().pairing(
			G2Element.generator().multiply(Scalar.fromNumber(12345)),
		);
		const key = kdf(x, new Uint8Array([]));
		expect(key).toEqual(
			fromHex('55e99a131b254f1687727bbf1f255e73bb80fcfac8901c371e53df32f45c1fb3'),
		);
	});

	it('test single key server', async () => {
		const [sk1, pk1] = generateKeyPair();

		const msg = new TextEncoder().encode('My super secret message');
		const aad = new Uint8Array([1, 2, 3, 4]);

		const objectId1 = '0x0000000000000000000000000000000000000000000000000000000000000001';

		const { encryptedObject } = await encrypt({
			keyServers: [
				{
					objectId: objectId1,
					pk: pk1.toBytes(),
					name: 'test',
					url: 'https://test.com',
					keyType: 0,
				},
			],
			kemType: KemType.BonehFranklinBLS12381DemCCA,
			threshold: 1,
			packageId: '0x0000000000000000000000000000000000000000000000000000000000000000',
			id: '01020304',
			encryptionInput: new AesGcm256(msg, aad),
		});

		const parsed = EncryptedObject.parse(encryptedObject);
		const id = createFullId(DST, parsed.packageId, parsed.id);
		const idBytes = fromHex(id);
		const usk1 = extractUserSecretKey(sk1, idBytes);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([[`${id}:${objectId1}`, usk1]]),
			}),
		).resolves.toEqual(msg);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>(),
			}),
		).rejects.toThrow();
	});

	it('test threshold = 1', async () => {
		const [sk1, pk1] = generateKeyPair();
		const [sk2, pk2] = generateKeyPair();
		const [, pk3] = generateKeyPair();

		const msg = new TextEncoder().encode('My super secret message');
		const aad = new Uint8Array([1, 2, 3, 4]);

		const objectId1 = '0x0000000000000000000000000000000000000000000000000000000000000001';
		const objectId2 = '0x0000000000000000000000000000000000000000000000000000000000000002';
		const objectId3 = '0x0000000000000000000000000000000000000000000000000000000000000003';

		const { encryptedObject } = await encrypt({
			keyServers: [
				{
					objectId: objectId1,
					pk: pk1.toBytes(),
					name: 'test',
					url: 'https://test.com',
					keyType: 0,
				},
				{
					objectId: objectId2,
					pk: pk2.toBytes(),
					name: 'test2',
					url: 'https://test2.com',
					keyType: 0,
				},
				{
					objectId: objectId3,
					pk: pk3.toBytes(),
					name: 'test3',
					url: 'https://test3.com',
					keyType: 0,
				},
			],
			kemType: KemType.BonehFranklinBLS12381DemCCA,
			threshold: 1,
			packageId: '0x0000000000000000000000000000000000000000000000000000000000000000',
			id: '01020304',
			encryptionInput: new AesGcm256(msg, aad),
		});

		const parsed = EncryptedObject.parse(encryptedObject);

		const id = createFullId(DST, parsed.packageId, parsed.id);
		const idBytes = fromHex(id);

		const usk1 = extractUserSecretKey(sk1, idBytes);
		const usk2 = extractUserSecretKey(sk2, idBytes);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([[`${id}:${objectId1}`, usk1]]),
			}),
		).resolves.toEqual(msg);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>([[`${id}:${objectId2}`, usk2]]),
			}),
		).resolves.toEqual(msg);

		await expect(
			decrypt({
				encryptedObject: parsed,
				keys: new Map<KeyCacheKey, G1Element>(),
			}),
		).rejects.toThrow();
	});
});
