// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 模块导出文件
 * 此文件导出SEAL库的主要组件，用于加密和密钥管理
 */

/**
 * 导出获取所有允许的密钥服务器的函数
 * 这些服务器用于分布式加密系统中的密钥管理
 */
export { getAllowlistedKeyServers } from './key-server.js';

/**
 * 导出SEAL客户端类及其配置选项
 * SealClient是与SEAL加密系统交互的主要接口
 */
export { SealClient, type SealClientOptions } from './client.js';

/**
 * 导出会话密钥类
 * 用于临时加密会话的密钥管理
 */
export { SessionKey } from './session-key.js';
