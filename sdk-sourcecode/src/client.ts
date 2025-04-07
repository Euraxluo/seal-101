// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * SEAL客户端实现文件
 * 提供加密和解密功能的主要客户端接口
 */

import type { SuiClient } from '@mysten/sui/client';

import { EncryptedObject } from './bcs.js';
import { G1Element, G2Element } from './bls12381.js';
import { decrypt } from './decrypt.js';
import type { EncryptionInput } from './dem.js';
import { AesGcm256, Hmac256Ctr } from './dem.js';
import { DemType, encrypt, KemType } from './encrypt.js';
import {
	InconsistentKeyServersError,
	InvalidKeyServerError,
	InvalidThresholdError,
	toMajorityError,
} from './error.js';
import { BonehFranklinBLS12381Services, DST } from './ibe.js';
import { KeyServerType, retrieveKeyServers, verifyKeyServer } from './key-server.js';
import type { KeyServer } from './key-server.js';
import { fetchKeysForAllIds } from './keys.js';
import type { SessionKey } from './session-key.js';
import type { KeyCacheKey } from './types.js';
import { createFullId } from './utils.js';

/**
 * SEAL客户端初始化配置选项
 * @property suiClient - Sui客户端实例，用于与区块链交互
 * @property serverObjectIds - 密钥服务器对象ID数组，用于指定要使用的密钥服务器
 * @property verifyKeyServers - 是否验证密钥服务器的真实性
 *   如果服务器已预先验证（例如使用getAllowlistedKeyServers），应设为false
 *   默认为true
 * @property timeout - 网络请求超时时间（毫秒），默认为10秒
 */
export interface SealClientOptions {
	suiClient: SuiClient;
	serverObjectIds: string[];
	verifyKeyServers?: boolean;
	timeout?: number;
}

/**
 * SEAL客户端类
 * 提供加密和解密功能的主要接口
 */
export class SealClient {
	#suiClient: SuiClient;
	#serverObjectIds: string[];
	#verifyKeyServers: boolean;
	#keyServers: Promise<KeyServer[]> | null = null;
	// 密钥缓存映射: fullId:object_id -> 部分密钥
	#cachedKeys = new Map<KeyCacheKey, G1Element>();
	#timeout: number;

	/**
	 * 创建SEAL客户端实例
	 * @param options - 客户端配置选项
	 */
	constructor(options: SealClientOptions) {
		this.#suiClient = options.suiClient;
		this.#serverObjectIds = options.serverObjectIds;
		this.#verifyKeyServers = options.verifyKeyServers ?? true;
		this.#timeout = options.timeout ?? 10_000;
	}

	/**
	 * 使用指定身份加密消息
	 *
	 * @param kemType - 使用的KEM(密钥封装机制)类型
	 * @param demType - 使用的DEM(数据封装机制)类型
	 * @param threshold - TSS加密的阈值
	 * @param packageId - 包ID命名空间
	 * @param id - 使用的身份
	 * @param data - 要加密的数据
	 * @param aad - 可选的额外认证数据
	 * @returns 加密对象的BCS字节和用于加密对象的256位对称密钥
	 *   由于对称密钥可用于解密，不应共享，但可用于备份等场景
	 */
	async encrypt({
		kemType = KemType.BonehFranklinBLS12381DemCCA,
		demType = DemType.AesGcm256,
		threshold,
		packageId,
		id,
		data,
		aad = new Uint8Array(),
	}: {
		kemType?: KemType;
		demType?: DemType;
		threshold: number;
		packageId: string;
		id: string;
		data: Uint8Array;
		aad?: Uint8Array;
	}) {
		// TODO: 验证packageId是其包的第一个版本(否则抛出错误)
		return encrypt({
			keyServers: await this.getKeyServers(),
			kemType,
			threshold,
			packageId,
			id,
			encryptionInput: this.#createEncryptionInput(demType, data, aad),
		});
	}

	/**
	 * 根据DEM类型创建相应的加密输入
	 * @param type - DEM类型
	 * @param data - 要加密的数据
	 * @param aad - 额外认证数据
	 * @returns 对应类型的加密输入对象
	 */
	#createEncryptionInput(type: DemType, data: Uint8Array, aad: Uint8Array): EncryptionInput {
		switch (type) {
			case DemType.AesGcm256:
				return new AesGcm256(data, aad);
			case DemType.Hmac256Ctr:
				return new Hmac256Ctr(data, aad);
		}
	}

	/**
	 * 使用缓存的密钥解密加密字节
	 * 如果一个或多个所需的密钥尚未缓存，则调用fetchKeys
	 * 如果客户端的密钥服务器不是加密对象的密钥服务器的子集(包括相同的权重)
	 * 或者无法满足阈值要求，函数将抛出错误
	 *
	 * @param data - 要解密的加密字节
	 * @param sessionKey - 要使用的会话密钥
	 * @param txBytes - 要使用的交易字节(调用seal_approve*函数)
	 * @returns 对应于密文的解密明文
	 */
	async decrypt({
		data,
		sessionKey,
		txBytes,
	}: {
		data: Uint8Array;
		sessionKey: SessionKey;
		txBytes: Uint8Array;
	}) {
		const encryptedObject = EncryptedObject.parse(data);

		this.#validateEncryptionServices(
			encryptedObject.services.map((s) => s[0]),
			encryptedObject.threshold,
		);

		await this.fetchKeys({
			ids: [encryptedObject.id],
			txBytes,
			sessionKey,
			threshold: encryptedObject.threshold,
		});

		return decrypt({ encryptedObject, keys: this.#cachedKeys });
	}

	/**
	 * 验证加密服务是否满足客户端要求
	 * @param services - 服务ID数组
	 * @param threshold - 阈值
	 * @throws 如果客户端密钥服务器不是加密对象密钥服务器的子集，或阈值无法满足
	 */
	#validateEncryptionServices(services: string[], threshold: number) {
		// 检查客户端的密钥服务器是否是加密对象的密钥服务器的子集
		const serverObjectIdsMap = new Map<string, number>();
		for (const objectId of this.#serverObjectIds) {
			serverObjectIdsMap.set(objectId, (serverObjectIdsMap.get(objectId) ?? 0) + 1);
		}
		const servicesMap = new Map<string, number>();
		for (const service of services) {
			servicesMap.set(service, (servicesMap.get(service) ?? 0) + 1);
		}
		for (const [objectId, count] of serverObjectIdsMap) {
			if (servicesMap.get(objectId) !== count) {
				throw new InconsistentKeyServersError(
					`客户端的密钥服务器必须是加密对象的密钥服务器的子集`,
				);
			}
		}
		// 检查是否可以用客户端的密钥服务器满足阈值
		if (threshold > this.#serverObjectIds.length) {
			throw new InvalidThresholdError(
				`无效的阈值 ${threshold}，服务器数量为 ${this.#serverObjectIds.length}`,
			);
		}
	}

	/**
	 * 获取密钥服务器列表
	 * @returns 密钥服务器数组
	 */
	async getKeyServers() {
		if (!this.#keyServers) {
			this.#keyServers = this.#loadKeyServers().catch((error) => {
				this.#keyServers = null;
				throw error;
			});
		}

		return this.#keyServers;
	}

	/**
	 * 加载密钥服务器
	 * @returns 密钥服务器数组
	 * @throws 如果未找到密钥服务器或验证失败
	 */
	async #loadKeyServers(): Promise<KeyServer[]> {
		const keyServers = await retrieveKeyServers({
			objectIds: this.#serverObjectIds,
			client: this.#suiClient,
		});

		if (keyServers.length === 0) {
			throw new InvalidKeyServerError('未找到密钥服务器');
		}

		if (this.#verifyKeyServers) {
			await Promise.all(
				keyServers.map(async (server) => {
					if (!(await verifyKeyServer(server, this.#timeout))) {
						throw new InvalidKeyServerError(`密钥服务器 ${server.objectId} 无效`);
					}
				}),
			);
		}

		return keyServers;
	}

	/**
	 * 从密钥服务器获取密钥并更新缓存
	 *
	 * 如果有多个加密对象，建议为所有对象的所有ID调用此函数一次，
	 * 然后为每个对象调用decrypt。这样可以避免为每个解密单独调用fetchKey。
	 *
	 * @param ids - 加密对象的ID
	 * @param txBytes - 要使用的交易字节(调用seal_approve*函数)
	 * @param sessionKey - 要使用的会话密钥
	 * @param threshold - TSS加密的阈值。当一个阈值的密钥服务器返回了所有ID的密钥时，函数返回
	 */
	async fetchKeys({
		ids,
		txBytes,
		sessionKey,
		threshold,
	}: {
		ids: string[];
		txBytes: Uint8Array;
		sessionKey: SessionKey;
		threshold: number;
	}) {
		const keyServers = await this.getKeyServers();
		if (threshold > keyServers.length || threshold < 1 || keyServers.length < 1) {
			throw new InvalidThresholdError(
				`无效的阈值 ${threshold}，服务器数量为 ${keyServers.length}`,
			);
		}

		let completedServerCount = 0;
		const remainingKeyServers = new Set<KeyServer>();
		const fullIds = ids.map((id) => createFullId(DST, sessionKey.getPackageId(), id));

		// 如果服务器拥有所有fullIds的密钥，则将其计为已完成
		// 重复的密钥服务器ID将计入阈值
		for (const server of keyServers) {
			let hasAllKeys = true;
			for (const fullId of fullIds) {
				if (!this.#cachedKeys.has(`${fullId}:${server.objectId}`)) {
					hasAllKeys = false;
					remainingKeyServers.add(server);
					break;
				}
			}
			if (hasAllKeys) {
				completedServerCount++;
			}
		}

		// 如果从缓存中有足够的密钥，提前返回
		if (completedServerCount >= threshold) {
			return;
		}

		// 检查服务器有效性
		for (const server of remainingKeyServers) {
			if (server.keyType !== KeyServerType.BonehFranklinBLS12381) {
				throw new InvalidKeyServerError(
					`服务器 ${server.objectId} 的密钥类型无效: ${server.keyType}`,
				);
			}
		}

		const cert = await sessionKey.getCertificate();
		const signedRequest = await sessionKey.createRequestParams(txBytes);

		const controller = new AbortController();
		const errors: Error[] = [];

		const keyFetches = [...remainingKeyServers].map(async (server) => {
			try {
				const allKeys = await fetchKeysForAllIds(
					server.url,
					signedRequest.requestSignature,
					txBytes,
					signedRequest.decryptionKey,
					cert,
					this.#timeout,
					controller.signal,
				);
				// 检查密钥的有效性并将其添加到缓存中
				let receivedIds = new Set<string>();
				for (const { fullId, key } of allKeys) {
					const keyElement = G1Element.fromBytes(key);
					if (
						!BonehFranklinBLS12381Services.verifyUserSecretKey(
							keyElement,
							fullId,
							G2Element.fromBytes(server.pk),
						)
					) {
						console.warn('从密钥服务器收到了无效的密钥 ' + server.objectId);
						continue;
					}
					this.#cachedKeys.set(`${fullId}:${server.objectId}`, keyElement);
					receivedIds.add(fullId);
				}

				// 检查所有接收到的ID是否与请求的fullIds一致
				// 如果是，则认为密钥服务器获取了所有密钥并标记为已完成
				const expectedIds = new Set(fullIds);
				const hasAllKeys =
					receivedIds.size === expectedIds.size &&
					[...receivedIds].every((id) => expectedIds.has(id));

				// 如果完成的服务器数量超过阈值，提前返回
				if (hasAllKeys) {
					completedServerCount++;
					if (completedServerCount >= threshold) {
						controller.abort();
					}
				}
			} catch (error) {
				if (!controller.signal.aborted) {
					errors.push(error as Error);
				}
				// 如果错误太多，导致无法达到阈值，则提前返回错误
				if (remainingKeyServers.size - errors.length < threshold - completedServerCount) {
					controller.abort(error);
				}
			}
		});

		await Promise.allSettled(keyFetches);

		if (completedServerCount < threshold) {
			throw toMajorityError(errors);
		}
	}
}
