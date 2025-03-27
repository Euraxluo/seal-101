// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 密钥服务器模块
 * 提供与SEAL密钥服务器交互的功能，包括获取密钥服务器信息和验证服务器有效性
 */

import { fromBase64, fromHex } from '@mysten/bcs';
import type { SuiClient } from '@mysten/sui/client';
import { bls12_381 } from '@noble/curves/bls12-381';

import { KeyServerMove } from './bcs.js';
import {
	InvalidGetObjectError,
	SealAPIError,
	UnsupportedFeatureError,
	UnsupportedNetworkError,
} from './error.js';
import { DST_POP } from './ibe.js';
import { PACKAGE_VERSION } from './version.js';

/**
 * 密钥服务器类型定义
 * 表示从链上获取的密钥服务器信息
 * @property objectId - 服务器对象ID
 * @property name - 服务器名称
 * @property url - 服务器URL
 * @property keyType - 密钥类型
 * @property pk - 公钥
 */
export type KeyServer = {
	objectId: string;
	name: string;
	url: string;
	keyType: KeyServerType;
	pk: Uint8Array;
};

/**
 * 密钥服务器类型枚举
 * 定义支持的密钥类型
 */
export enum KeyServerType {
	/**
	 * 基于BLS12-381曲线的Boneh-Franklin IBE方案
	 */
	BonehFranklinBLS12381 = 0,
}

/**
 * 返回应用程序可以选择使用的SEAL密钥服务器对象ID的静态列表
 * 这些服务器是经过预先验证和允许的
 * 
 * @param network - 要使用的网络(testnet或mainnet)
 * @returns 密钥服务器的对象ID列表
 * @throws 如果网络不受支持
 */
export function getAllowlistedKeyServers(network: 'testnet' | 'mainnet'): string[] {
	if (network === 'testnet') {
		return [
			'0xb35a7228d8cf224ad1e828c0217c95a5153bafc2906d6f9c178197dce26fbcf8',
			'0x2d6cde8a9d9a65bde3b0a346566945a63b4bfb70e9a06c41bdb70807e2502b06',
		];
	} else {
		throw new UnsupportedNetworkError(`不支持的网络 ${network}`);
	}
}

/**
 * 根据密钥服务器对象ID列表，从链上状态获取密钥服务器信息
 * 包括名称、对象ID、URL和公钥
 *
 * @param objectIds - 密钥服务器对象ID列表
 * @param client - 使用的SuiClient
 * @returns 密钥服务器信息数组
 * @throws 如果找不到密钥服务器或查询无效
 */
export async function retrieveKeyServers({
	objectIds,
	client,
}: {
	objectIds: string[];
	client: SuiClient;
}): Promise<KeyServer[]> {
	// 待办: 如果之前已获取过相同的对象ID，则不再重复获取
	return await Promise.all(
		objectIds.map(async (objectId) => {
			const res = await client.getObject({
				id: objectId,
				options: {
					showBcs: true,
				},
			});
			if (!res || res.error || !res.data) {
				throw new InvalidGetObjectError(`未找到密钥服务器 ${objectId}; ${res.error}`);
			}

			if (!res.data.bcs || !('bcsBytes' in res.data.bcs)) {
				throw new InvalidGetObjectError(
					`无效的密钥服务器查询: ${objectId}, 预期对象，但得到包`,
				);
			}

			let ks = KeyServerMove.parse(fromBase64(res.data.bcs!.bcsBytes));
			if (ks.keyType !== 0) {
				throw new UnsupportedFeatureError(`不支持的密钥类型 ${ks.keyType}`);
			}

			return {
				objectId,
				name: ks.name,
				url: ks.url,
				keyType: KeyServerType.BonehFranklinBLS12381,
				pk: new Uint8Array(ks.pk),
			};
		}),
	);
}

/**
 * 验证密钥服务器的有效性
 * 从URL获取持有证明(PoP)并验证其与公钥的一致性
 * 当应用程序使用动态密钥服务器集时，应仅偶尔使用此功能
 *
 * @param server - 要验证的密钥服务器
 * @param timeout - 请求超时时间(毫秒)
 * @returns 如果密钥服务器有效则返回true，否则返回false
 */
export async function verifyKeyServer(server: KeyServer, timeout: number): Promise<boolean> {
	const requestId = crypto.randomUUID();
	const response = await fetch(server.url! + '/v1/service', {
		method: 'GET',
		headers: {
			'Content-Type': 'application/json',
			'Request-Id': requestId,
			'Client-Sdk-Type': 'typescript',
			'Client-Sdk-Version': PACKAGE_VERSION,
		},
		signal: AbortSignal.timeout(timeout),
	});

	await SealAPIError.assertResponse(response, requestId);
	const serviceResponse = await response.json();

	if (serviceResponse.service_id !== server.objectId) {
		return false;
	}
	const fullMsg = new Uint8Array([...DST_POP, ...server.pk, ...fromHex(server.objectId)]);
	return bls12_381.verifyShortSignature(fromBase64(serviceResponse.pop), fullMsg, server.pk);
}
