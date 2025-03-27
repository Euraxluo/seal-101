// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 会话密钥模块
 * 提供临时会话密钥的创建和管理功能
 * 用于安全地与密钥服务器通信
 */

import { toBase64 } from '@mysten/bcs';
import { bcs } from '@mysten/sui/bcs';
import type { Signer } from '@mysten/sui/cryptography';
import { SuiGraphQLClient } from '@mysten/sui/graphql';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { isValidSuiAddress, isValidSuiObjectId } from '@mysten/sui/utils';
import { verifyPersonalMessageSignature } from '@mysten/sui/verify';

import { generateSecretKey, toPublicKey, toVerificationKey } from './elgamal.js';
import {
	ExpiredSessionKeyError,
	InvalidPersonalMessageSignatureError,
	UserError,
} from './error.js';

/**
 * 请求格式的BCS结构定义
 * 包含预编译交易块(PTB)和加密密钥信息
 */
export const RequestFormat = bcs.struct('RequestFormat', {
	ptb: bcs.vector(bcs.U8),
	encKey: bcs.vector(bcs.U8),
	encVerificationKey: bcs.vector(bcs.U8),
});

/**
 * 证书类型定义
 * 用于向密钥服务器证明用户身份和会话有效性
 */
export type Certificate = {
	user: string;
	session_vk: string;
	creation_time: number;
	ttl_min: number;
	signature: string;
};

/**
 * 会话密钥类
 * 管理临时会话密钥的生命周期和相关操作
 */
export class SessionKey {
	#address: string;
	#packageId: string;
	#creationTimeMs: number;
	#ttlMin: number;
	#sessionKey: Ed25519Keypair;
	#personalMessageSignature?: string;
	#signer?: Signer;

	/**
	 * 创建会话密钥实例
	 */
	constructor({
		address,
		packageId,
		ttlMin,
		signer,
	}: {
		address: string;
		packageId: string;
		ttlMin: number;
		signer?: Signer;
	}) {
		if (!isValidSuiObjectId(packageId) || !isValidSuiAddress(address)) {
			throw new UserError(`无效的包ID ${packageId} 或地址 ${address}`);
		}
		if (ttlMin > 10 || ttlMin < 1) {
			throw new UserError(`无效的TTL ${ttlMin}，必须在1到10之间`);
		}

		this.#address = address;
		this.#packageId = packageId;
		this.#creationTimeMs = Date.now();
		this.#ttlMin = ttlMin;
		this.#sessionKey = Ed25519Keypair.generate();
		this.#signer = signer;
	}

	/**
	 * 检查会话密钥是否已过期
	 * 允许10秒的时钟偏差
	 */
	isExpired(): boolean {
		// 允许10秒的时钟偏差
		return this.#creationTimeMs + this.#ttlMin * 60 * 1000 - 10_000 < Date.now();
	}

	/**
	 * 获取用户地址
	 */
	getAddress(): string {
		return this.#address;
	}

	/**
	 * 获取包ID
	 */
	getPackageId(): string {
		return this.#packageId;
	}

	/**
	 * 获取需要用户签名的个人消息
	 * 消息包含包ID、TTL、创建时间和会话公钥
	 */
	getPersonalMessage(): Uint8Array {
		const creationTimeUtc =
			new Date(this.#creationTimeMs).toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
		const message = `Accessing keys of package ${this.#packageId} for ${this.#ttlMin} mins from ${creationTimeUtc}, session key ${toBase64(this.#sessionKey.getPublicKey().toRawBytes())}`;
		return new TextEncoder().encode(message);
	}

	/**
	 * 设置个人消息的签名
	 * 验证签名有效性，然后存储用于后续操作
	 */
	async setPersonalMessageSignature(personalMessageSignature: string) {
		try {
			// TODO: 修复此处以适用于任何网络
			await verifyPersonalMessageSignature(this.getPersonalMessage(), personalMessageSignature, {
				address: this.#address,
				client: new SuiGraphQLClient({
					url: 'https://sui-testnet.mystenlabs.com/graphql',
				}),
			});
			this.#personalMessageSignature = personalMessageSignature;
		} catch (e) {
			throw new InvalidPersonalMessageSignatureError('无效的签名');
		}
	}

	/**
	 * 获取证书
	 * 证书用于向密钥服务器证明用户身份和会话有效性
	 */
	async getCertificate(): Promise<Certificate> {
		if (!this.#personalMessageSignature) {
			if (this.#signer) {
				const { signature } = await this.#signer.signPersonalMessage(this.getPersonalMessage());
				this.#personalMessageSignature = signature;
			} else {
				throw new InvalidPersonalMessageSignatureError('未设置个人消息签名');
			}
		}
		return {
			user: this.#address,
			session_vk: toBase64(this.#sessionKey.getPublicKey().toRawBytes()),
			creation_time: this.#creationTimeMs,
			ttl_min: this.#ttlMin,
			signature: this.#personalMessageSignature,
		};
	}

	/**
	 * 创建请求参数
	 * 为密钥服务器请求生成必要的参数
	 */
	async createRequestParams(
		txBytes: Uint8Array,
	): Promise<{ decryptionKey: Uint8Array; requestSignature: string }> {
		if (this.isExpired()) {
			throw new ExpiredSessionKeyError();
		}
		const egSk = generateSecretKey();
		const msgToSign = RequestFormat.serialize({
			ptb: txBytes.slice(1),
			encKey: toPublicKey(egSk),
			encVerificationKey: toVerificationKey(egSk),
		}).toBytes();
		return {
			decryptionKey: egSk,
			requestSignature: toBase64(await this.#sessionKey.sign(msgToSign)),
		};
	}
}
