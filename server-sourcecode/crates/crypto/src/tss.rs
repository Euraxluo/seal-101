// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 阈值秘密共享模块
 * 
 * 本模块实现了一个基于Shamir秘密共享的阈值秘密共享方案。
 * 可以共享任意32字节的秘密，并且要求至少有阈值(threshold)数量的份额才能重构秘密。
 * 该实现基于GF(256)有限域进行多项式插值。
 * 
 * 主要功能:
 * 1. 将秘密分割成多个份额
 * 2. 从足够数量的份额重构秘密
 * 3. 在指定点评估插值多项式
 */

use crate::gf256::GF256;
use crate::polynomial::Polynomial;
use crate::utils::transpose;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use std::iter::repeat_with;

/// 秘密共享结构体，包含原始秘密、份额索引和份额内容
pub struct SecretSharing<const N: usize> {
    pub(crate) secret: [u8; N],        // 原始秘密
    pub(crate) indices: Vec<u8>,        // 份额的索引值
    pub(crate) shares: Vec<[u8; N]>,    // 份额内容
}

impl<const N: usize> SecretSharing<N> {
    /// 获取所有份额
    pub fn shares(&self) -> &[[u8; N]] {
        &self.shares
    }

    /// 获取所有份额的索引
    pub fn indices(&self) -> &[u8] {
        &self.indices
    }

    /// 获取原始秘密
    pub fn secret(&self) -> &[u8; N] {
        &self.secret
    }
}

/**
 * 将秘密分割成多个份额
 * 
 * 该函数实现了Shamir的秘密共享算法，将一个秘密分割成`number_of_shares`个份额，
 * 其中至少需要`threshold`个份额才能重构出原始秘密。
 * 
 * 参数:
 * @param rng - 随机数生成器，用于生成随机多项式系数
 * @param secret - 要共享的秘密
 * @param threshold - 重构秘密所需的最小份额数量
 * @param number_of_shares - 要生成的份额总数
 * 
 * 返回:
 * 包含秘密和份额的SecretSharing结构
 */
pub fn split<R: AllowedRng, const N: usize>(
    rng: &mut R,
    secret: [u8; N],
    threshold: u8,
    number_of_shares: u8,
) -> FastCryptoResult<SecretSharing<N>> {
    if threshold > number_of_shares || threshold == 0 {
        return Err(InvalidInput);
    }

    let indices = (1..=number_of_shares).collect_vec();

    // 对秘密的每个字节单独进行共享
    let byte_shares = secret
        .iter()
        .map(|b| split_byte(rng, *b, threshold, &indices))
        .collect::<FastCryptoResult<Vec<_>>>()?;

    // 将字节份额组合成完整份额
    let shares = transpose(&byte_shares)?;

    Ok(SecretSharing {
        secret,
        indices,
        shares,
    })
}

/**
 * 根据份额集合插值多项式，并返回一个闭包用于在指定点评估多项式
 * 
 * 如果份额数量少于阈值或某些份额无效，结果将是错误的，但不会返回错误。
 * 如果份额的索引不唯一或集合为空，将返回InvalidInput错误。
 * 
 * 参数:
 * @param shares - 份额集合，每个元素为(索引, 份额内容)对
 * 
 * 返回:
 * 一个闭包，接受一个点并返回在该点处的多项式值
 */
pub fn interpolate<const N: usize>(
    shares: &[(u8, [u8; N])],
) -> FastCryptoResult<impl Fn(u8) -> [u8; N]> {
    if shares.is_empty()
        || shares.iter().any(|(i, _)| *i == 0)
        || !shares.iter().map(|(i, _)| i).all_unique()
    {
        return Err(InvalidInput);
    }

    // 为秘密的每个字节创建一个插值多项式
    let polynomials: Vec<Polynomial> = (0..N)
        .map(|i| {
            Polynomial::interpolate(
                &shares
                    .iter()
                    .map(|(index, share)| (GF256(*index), GF256(share[i])))
                    .collect_vec(),
            )
        })
        .collect();

    // 返回一个闭包，用于在给定点评估所有多项式
    Ok(move |x: u8| {
        polynomials
            .iter()
            .map(|p| p.evaluate(&GF256(x)).into())
            .collect_vec()
            .try_into()
            .expect("Fixed length")
    })
}

/**
 * 从一组份额重构秘密
 * 
 * 使用Lagrange插值公式从份额集合中恢复原始秘密。
 * 如果份额数量少于阈值或某些份额无效，结果将是错误的，但不会返回错误。
 * 如果份额的索引不唯一或集合为空，将返回InvalidInput错误。
 * 
 * 参数:
 * @param shares - 份额集合，每个元素为(索引, 份额内容)对
 * 
 * 返回:
 * 重构的秘密
 */
pub fn combine<const N: usize>(shares: &[(u8, [u8; N])]) -> FastCryptoResult<[u8; N]> {
    Ok((0..N)
        .map(|i| {
            combine_byte(
                &shares
                    .iter()
                    .map(|share| (share.0, share.1[i]))
                    .collect_vec(),
            )
        })
        .collect::<FastCryptoResult<Vec<_>>>()?
        .try_into()
        .expect("fixed length"))
}

/**
 * 使用给定的份额创建秘密共享
 * 
 * 该函数根据已知的一些份额创建一个秘密共享，秘密值由给定的份额确定。
 * 
 * 参数:
 * @param given_shares - 已知的份额
 * @param number_of_shares - 要生成的份额总数
 * 
 * 返回:
 * 包含秘密和份额的SecretSharing结构
 */
pub fn split_with_given_shares<const N: usize>(
    given_shares: &[[u8; N]],
    number_of_shares: u8,
) -> FastCryptoResult<SecretSharing<N>> {
    let threshold = given_shares.len();
    if threshold > number_of_shares as usize || threshold == 0 {
        return Err(InvalidInput);
    }

    let indices = (1..=number_of_shares).collect_vec();

    // 对每个字节单独进行处理
    let (secret, byte_shares): (Vec<u8>, Vec<Vec<u8>>) = (0..N)
        .map(|i| {
            split_byte_with_given_shares(&given_shares.iter().map(|s| s[i]).collect_vec(), &indices)
        })
        .collect::<FastCryptoResult<Vec<_>>>()?
        .into_iter()
        .unzip();

    // 组合字节份额成完整份额
    let shares = transpose(&byte_shares)?;
    let secret = secret.try_into().expect("fixed length");

    Ok(SecretSharing {
        secret,
        indices,
        shares,
    })
}

/**
 * 内部函数：共享单个字节的秘密
 * 
 * 这是Shamir秘密共享在GF(256)有限域上的实现。
 * 参考文献: https://dl.acm.org/doi/10.1145/359168.359176
 * 
 * 参数:
 * @param rng - 随机数生成器
 * @param secret - 要共享的字节秘密
 * @param threshold - 重构秘密所需的最小份额数
 * @param indices - 份额索引列表
 * 
 * 返回:
 * 份额字节列表
 */
fn split_byte<R: AllowedRng>(
    rng: &mut R,
    secret: u8,
    threshold: u8,
    indices: &[u8],
) -> FastCryptoResult<Vec<u8>> {
    let number_of_shares = indices.len() as u8;
    if threshold == 0
        || number_of_shares == 0
        || threshold > number_of_shares
        || indices.iter().any(|i| *i == 0)
        || !indices.iter().all_unique()
    {
        return Err(InvalidInput);
    }

    // 构造一个度为`threshold - 1`的随机多项式，常数项为秘密值
    let mut coefficients = Vec::with_capacity(threshold as usize);
    coefficients.push(GF256::from(secret));
    coefficients.extend(repeat_with(|| GF256::rand(rng)).take((threshold - 1) as usize));
    let polynomial = Polynomial(coefficients);
    Ok(indices
        .iter()
        .map(|i| polynomial.evaluate(&i.into()).into())
        .collect())
}

/**
 * 创建带有指定份额的秘密共享
 * 
 * 创建一个秘密共享，使得至少需要`threshold`个份额才能重构字节，且前`threshold`个份额就是给定的份额。
 * 共享的秘密由给定的份额决定，且这个过程是确定性的。
 * 
 * 参数:
 * @param given_shares - 给定的份额
 * @param indices - 份额索引列表
 * 
 * 返回:
 * 秘密值和所有份额的元组
 */
fn split_byte_with_given_shares(
    given_shares: &[u8],
    indices: &[u8],
) -> FastCryptoResult<(u8, Vec<u8>)> {
    let number_of_shares = indices.len();
    let threshold = given_shares.len() + 1;
    assert!(threshold <= number_of_shares && number_of_shares <= 255 && threshold > 0);
    assert!(indices.iter().all(|&i| i != 0) && indices.iter().all_unique());

    // 构建插值给定份额和秘密的多项式
    let polynomial = Polynomial::interpolate(
        &indices
            .iter()
            .zip(given_shares)
            .map(|(&x, &y)| (x.into(), y.into()))
            .collect_vec(),
    );

    // 秘密是多项式的常数项
    let secret = polynomial.0[0].0;

    // 在剩余索引处评估多项式以获得剩余份额
    let remaining_shares = indices[given_shares.len()..]
        .iter()
        .map(|i| polynomial.evaluate(&i.into()).0)
        .collect();

    let shares = [given_shares.to_vec(), remaining_shares].concat();

    Ok((secret, shares))
}

/**
 * 内部函数：从份额重构单个字节的秘密
 * 
 * 这是Shamir秘密共享在GF(256)有限域上的实现。
 * 参考文献: https://dl.acm.org/doi/10.1145/359168.359176
 * 
 * 参数:
 * @param shares - 份额集合，每个元素为(索引, 份额值)对
 * 
 * 返回:
 * 重构的字节秘密
 */
fn combine_byte(shares: &[(u8, u8)]) -> FastCryptoResult<u8> {
    if shares.is_empty()
        || !shares.iter().map(|(i, _)| i).all_unique()
        || shares.iter().any(|(i, _)| *i == 0)
    {
        return Err(InvalidInput);
    }
    let product: GF256 = shares.iter().map(|(i, _)| GF256::from(i)).product();
    let quotient: GF256 = shares
        .iter()
        .map(|(i, share_i)| {
            let denominator = &GF256::from(*i)
                * &shares
                    .iter()
                    .map(|(j, _)| j)
                    .filter(|j| j != &i)
                    .map(|j| &GF256::from(j) - &GF256::from(i))
                    .product();
            (&GF256::from(share_i) / &denominator).unwrap()
        })
        .sum();
    Ok((&product * &quotient).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::encoding::{Base64, Encoding};
    use rand::thread_rng;

    /// 测试单字节组合函数
    /// 验证combine_byte函数能够正确重建秘密值
    #[test]
    fn test_combine_byte() {
        let x = vec![(1, 2), (2, 3), (3, 4), (4, 5)];
        assert_eq!(combine_byte(&x).unwrap(), 202);
    }

    /// 测试秘密共享的分割和重建过程
    /// 1. 使用阈值3分割秘密
    /// 2. 验证不同组合的至少3个份额可以重建秘密
    /// 3. 验证少于阈值的份额无法正确重建秘密
    /// 4. 验证非法输入的错误处理
    #[test]
    fn test_secret_sharing() {
        // 测试秘密
        let secret = *b"For sale: baby shoes, never worn";

        // 使用阈值3分割秘密为5个份额
        let SecretSharing {
            indices, shares, ..
        } = split(&mut thread_rng(), secret, 3, 5).unwrap();

        // 验证不同组合的3个或更多份额可以重建秘密
        assert_eq!(
            secret,
            combine(&(1..4).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );
        assert_eq!(
            secret,
            combine(&(0..3).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );
        assert_eq!(
            secret,
            combine(&(0..4).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );
        assert_eq!(
            secret,
            combine(&(2..5).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );

        // 验证少于阈值(3)的份额无法正确重建秘密
        assert_ne!(
            secret,
            combine(&(0..2).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );

        // 验证空份额集合和重复索引会返回错误
        assert!(combine::<32>(&[]).is_err());
        assert!(combine(&[(indices[0], shares[0]), (indices[0], shares[0])]).is_err());
    }

    /// 测试无效份额输入的错误处理
    /// 验证combine函数对非法输入的正确处理
    #[test]
    fn test_invalid_shares() {
        let share1 = [1; 32];
        let share2 = [2; 32];

        // 验证重复索引会返回错误
        assert!(combine(&[(1u8, share1), (1u8, share2)]).is_err());

        // 验证空份额集合会返回错误
        assert!(combine::<32>(&[]).is_err());
    }

    /// 测试与TypeScript实现的兼容性
    /// 使用预定义的测试向量确保跨语言实现的一致性
    #[test]
    fn typescript_test_vector() {
        const N: usize = 23;
        let expected = *b"My super secret message";
        assert_eq!(expected.len(), N);

        // 从Base64字符串解析2/3阈值共享的份额
        let shares = vec![
            "C7rQzQ0iL+L+fBcIAZipXBhtZsUju7ot",
            "lO0Boejog7ARBVXjjLUMqAFP/Iut0ZpZ",
            "FsrVroJ5+eWfw7sFgXq8Y3AWDN2Ogvc9",
        ]
        .into_iter()
        .map(Base64::decode)
        .collect::<FastCryptoResult<Vec<_>>>()
        .unwrap();
        
        // 提取份额索引和内容
        let shares = shares
            .iter()
            .map(|bytes| (bytes[N], bytes[..N].try_into().unwrap()))
            .collect::<Vec<_>>();
            
        // 验证不同组合的份额重建结果
        assert_eq!(combine(&shares[..2]).unwrap(), expected);  // 使用前2个份额
        assert_eq!(combine(&shares[1..3]).unwrap(), expected); // 使用后2个份额
        assert_eq!(combine(&shares).unwrap(), expected);       // 使用全部3个份额

        // 验证少于阈值的份额无法正确重建秘密
        assert_ne!(combine(&shares[..1]).unwrap(), expected);  // 只用1个份额
    }

    /// 测试带有预定义份额的字节级秘密分割
    /// 验证split_byte_with_given_shares函数的正确性
    #[test]
    fn test_split_byte_with_given_shares() {
        // 预定义的份额和索引
        let given_shares = [5, 19];
        let indices = [1, 2, 3, 4, 5];

        // 使用预定义份额分割秘密
        let (secret, shares) = split_byte_with_given_shares(&given_shares, &indices).unwrap();

        // 验证可以使用不同组合的份额重建秘密
        let reconstructed = combine_byte(&[
            (indices[0], shares[0]),
            (indices[2], shares[2]),
            (indices[4], shares[4]),
        ])
        .unwrap();
        assert_eq!(reconstructed, secret);
    }

    /// 测试带有预定义份额的秘密分割
    /// 验证split_with_given_shares函数的正确性
    #[test]
    fn test_with_given_shares() {
        // 预定义的份额
        let given_shares = [
            *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            *b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            *b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        ];
        let threshold = given_shares.len() as u8;
        
        // 使用预定义份额分割秘密
        let SecretSharing {
            secret,
            indices,
            shares,
        } = split_with_given_shares(&given_shares, 5).unwrap();

        // 验证基本属性
        assert_eq!(threshold, given_shares.len() as u8);
        assert_eq!(shares[0], given_shares[0]);
        assert_eq!(shares[1], given_shares[1]);

        // 验证可以使用不同份额组合重建秘密
        assert_eq!(
            secret,
            combine(&(1..4).map(|i| (indices[i], shares[i])).collect_vec()).unwrap()
        );
    }
}
