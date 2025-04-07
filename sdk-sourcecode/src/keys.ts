// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 密钥获取模块
 * 提供从密钥服务器获取和处理密钥的功能
 */

import { fromBase64, toBase64, toHex } from '@mysten/bcs';

import { elgamalDecrypt, toPublicKey, toVerificationKey } from './elgamal.js';
import { SealAPIError } from './error.js';
import type { Certificate } from './session-key.js';
import { PACKAGE_VERSION } from './version.js';

/**
 * 辅助函数，用于从URL请求所有密钥
 * 使用请求签名、交易字节和临时公钥进行请求
 * 然后使用临时私钥解密SEAL密钥
 * 返回带有完整ID的解密密钥列表
 *
 * @param url - 密钥服务器的URL
 * @param requestSig - 请求签名的Base64字符串
 * @param txBytes - 交易字节
 * @param encKey - 临时私钥
 * @param certificate - 证书
 * @param timeout - 请求超时时间(毫秒)
 * @param signal - 可选的中止信号，用于取消请求
 * @returns 完整ID和解密密钥的列表
 */
export async function fetchKeysForAllIds(
	url: string,
	requestSig: string,
	txBytes: Uint8Array,
	encKey: Uint8Array,
	certificate: Certificate,
	timeout: number,
	signal?: AbortSignal,
): Promise<{ fullId: string; key: Uint8Array }[]> {
	// 从私钥生成公钥和验证密钥
	const encKeyPk = toPublicKey(encKey);
	const encVerificationKey = toVerificationKey(encKey);
	// 构建请求体
	const body = {
		ptb: toBase64(txBytes.slice(1)), // 移除交易类型版本的字节
		enc_key: toBase64(encKeyPk),
		enc_verification_key: toBase64(encVerificationKey),
		request_signature: requestSig, // 已经是b64格式
		certificate,
	};

	// 创建超时信号和组合信号
	const timeoutSignal = AbortSignal.timeout(timeout);
	const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

	// 生成请求ID并发送请求
	const requestId = crypto.randomUUID();
	const response = await fetch(url + '/v1/fetch_key', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Request-Id': requestId,
			'Client-Sdk-Type': 'typescript',
			'Client-Sdk-Version': PACKAGE_VERSION,
		},
		body: JSON.stringify(body),
		signal: combinedSignal,
	});
	// 检查响应是否成功
	await SealAPIError.assertResponse(response, requestId);

	// 处理响应数据
	const resp = await response.json();
	// 将每个加密密钥解密并返回结果
	return resp.decryption_keys.map((dk: { id: Uint8Array; encrypted_key: [string, string] }) => ({
		fullId: toHex(new Uint8Array(dk.id)),
		key: elgamalDecrypt(encKey, dk.encrypted_key.map(fromBase64) as [Uint8Array, Uint8Array]),
	}));
}
