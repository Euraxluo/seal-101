// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 密钥服务器测试文件
 * 测试与SEAL密钥服务器相关的功能
 * 包括获取密钥服务器列表、验证密钥服务器等
 */

import { fromBase64 } from '@mysten/bcs';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { GeneralError } from '../../src/error.js';
import {
	getAllowlistedKeyServers,
	retrieveKeyServers,
	verifyKeyServer,
} from '../../src/key-server.js';

// 用于SuiClient模拟响应的数据
const pk = fromBase64(
	'oEC1VIuwQo+6FZiVwHCAy/3HbvAbuIyiztXIWwd4LgmXCh9WhOKg3T0+Mb62y9fqAsSaN5SybG09n/3JnkmEzJgdDXLpM8KvMwkha/cBHp6Cx7aCdogvGLoOp/RadyHb',
);
const id = '0xb35a7228d8cf224ad1e828c0217c95a5153bafc2906d6f9c178197dce26fbcf8';
const keyType = 0;
const url = 'https://seal-key-server-testnet-1.mystenlabs.com';
const name = 'mysten-testnet-1';

describe('key-server tests', () => {
	/**
	 * 测试前准备：模拟SuiClient
	 * 设置模拟的SuiClient返回预定义的密钥服务器信息
	 */
	beforeEach(() => {
		vi.mock('@mysten/sui.js', () => ({
			SuiClient: vi.fn(() => ({
				getObject: vi.fn().mockResolvedValue({
					data: {
						content: {
							fields: {
								id: {
									id,
								},
								name,
								url,
								key_type: keyType,
								pk,
							},
						},
					},
				}),
			})),
		}));
	});

	/**
	 * 测试后清理：清除所有模拟
	 */
	afterEach(() => {
		vi.clearAllMocks();
	});

	/**
	 * 测试获取预设的允许的密钥服务器列表
	 * 验证testnet环境下的允许密钥服务器ID列表
	 */
	it('test fixed getAllowedlistedKeyServers', async () => {
		// 这些ID应该随着新密钥服务器的添加而更新
		expect(getAllowlistedKeyServers('testnet')).toEqual([
			'0xb35a7228d8cf224ad1e828c0217c95a5153bafc2906d6f9c178197dce26fbcf8',
			'0x2d6cde8a9d9a65bde3b0a346566945a63b4bfb70e9a06c41bdb70807e2502b06',
		]);
	});

	/**
	 * 测试从链上获取密钥服务器信息
	 * 验证retrieveKeyServers函数正确解析链上数据
	 */
	it('test retrieveKeyServers (mocked)', async () => {
		const keyServers = await retrieveKeyServers({
			objectIds: [id],
			client: new SuiClient({ url: getFullnodeUrl('testnet') }),
		});
		// 验证返回的服务器信息正确
		expect(keyServers.length).toEqual(1);
		expect(keyServers[0].objectId).toEqual(id);
		expect(keyServers[0].name).toEqual(name);
		expect(keyServers[0].keyType).toEqual(0);
		expect(keyServers[0].url).toEqual(url);
		expect(keyServers[0].pk).toEqual(new Uint8Array(pk));
	});

	/**
	 * 测试验证密钥服务器信息
	 * 验证verifyKeyServer函数正确验证服务器持有证明(PoP)
	 */
	it('test verifyKeyServerInfo (mocked)', async () => {
		// 模拟真实服务响应，获取密钥服务器信息
		const keyServers = await retrieveKeyServers({
			objectIds: [id],
			client: new SuiClient({ url: getFullnodeUrl('testnet') }),
		});
		vi.clearAllMocks();
		// 模拟fetch请求返回正确的服务器信息和证明
		global.fetch = vi.fn().mockImplementation(() => {
			return Promise.resolve({
				ok: true,
				status: 200,
				json: () =>
					Promise.resolve({
						service_id: id, // 注意：实际响应使用十六进制字符串格式
						pop: 'iDsj79BrG4PplI8oxRR3OUS6STJkC1ffoljGwSlk2BWib4ovohsk2/irjkqdOEkF',
					}),
			});
		});

		// 验证服务器信息
		expect(verifyKeyServer(keyServers[0], 10_000)).toBeTruthy();
	});

	/**
	 * 测试服务器返回错误状态时的处理
	 * 验证当服务器返回503状态码时抛出正确的错误
	 */
	it('test verifyKeyServer throws SealAPIError on 503', async () => {
		const keyServers = [
			{
				objectId: id,
				name,
				keyType,
				url,
				pk,
			},
		];
		// 模拟服务器返回503错误
		global.fetch = vi.fn().mockImplementation(() => {
			return Promise.resolve({
				ok: false,
				status: 503,
				text: () => Promise.resolve('Internal server error, please try again later'),
			});
		});

		// 验证函数抛出GeneralError
		await expect(verifyKeyServer(keyServers[0], 10_000)).rejects.toThrow(GeneralError);
	});
});
