// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 实用工具模块
 * 
 * 本模块提供了一系列加密操作中常用的工具函数，包括：
 * 1. 字节数组异或操作
 * 2. 随机字节生成
 * 3. 矩阵转置（用于秘密共享中处理字节矩阵）
 * 
 * 这些工具函数主要供密钥管理系统的其他组件内部使用。
 */

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;

/**
 * 对两个固定长度的字节数组执行异或操作
 * 
 * 参数:
 * @param a - 第一个字节数组
 * @param b - 第二个字节数组
 * 
 * 返回:
 * 异或结果的字节数组
 */
pub(crate) fn xor<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    xor_unchecked(a, b)
        .try_into()
        .expect("Inputs are guaranteed to have the same lengths")
}

/**
 * 对两个字节切片执行异或操作
 * 如果一个切片比另一个短，结果将以较短切片的长度为准
 * 
 * 参数:
 * @param a - 第一个字节切片
 * @param b - 第二个字节切片
 * 
 * 返回:
 * 异或结果的字节向量
 */
pub(crate) fn xor_unchecked(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/**
 * 生成指定长度的随机字节数组
 * 
 * 参数:
 * @param rng - 随机数生成器
 * 
 * 返回:
 * 生成的随机字节数组
 */
pub(crate) fn generate_random_bytes<R: AllowedRng, const N: usize>(rng: &mut R) -> [u8; N] {
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

/**
 * 转置字节矩阵
 * 
 * 将N个长度为M的向量转换为M个长度为N的数组，使得matrix[i][j] = transpose(&matrix)[j][i]
 * 这个函数在秘密共享算法中用于处理份额矩阵
 * 
 * 参数:
 * @param matrix - 要转置的矩阵（向量的向量）
 * 
 * 返回:
 * 转置后的矩阵，如果输入无效则返回错误
 * 
 * 错误:
 * - 如果输入向量长度不等于N
 * - 如果输入为空
 * - 如果输入向量中的元素长度不一致
 */
pub(crate) fn transpose<const N: usize>(matrix: &[Vec<u8>]) -> FastCryptoResult<Vec<[u8; N]>> {
    if matrix.len() != N || matrix.is_empty() {
        return Err(InvalidInput);
    }
    let m = matrix
        .iter()
        .map(Vec::len)
        .all_equal_value()
        .map_err(|_| InvalidInput)?;

    Ok((0..m)
        .map(|i| {
            matrix
                .iter()
                .map(|row| row[i])
                .collect_vec()
                .try_into()
                .expect("This will never fail since the length is guaranteed to be N")
        })
        .collect())
}
