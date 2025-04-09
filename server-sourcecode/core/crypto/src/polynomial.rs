// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 多项式计算模块
 * 
 * 本模块实现了GF(256)有限域上的多项式表示和操作。
 * 这些多项式被广泛用于:
 * 1. Shamir秘密共享方案 - 用于安全分发密钥
 * 2. Reed-Solomon编码 - 用于纠错码
 * 3. 多项式插值 - 在多方计算中恢复秘密
 * 
 * 多项式表示为系数向量，从常数项（x⁰的系数）开始到最高次项。
 * 例如，多项式 3x² + 2x + 1 表示为向量 [1, 2, 3]。
 * 
 * 主要功能:
 * - 多项式求值
 * - 多项式加法、乘法和标量除法
 * - Lagrange多项式插值
 */

use crate::gf256::GF256;
use fastcrypto::error::FastCryptoResult;
use itertools::Itertools;
use std::iter::{Product, Sum};
use std::ops::{Add, Div, Mul};
use std::{unreachable, vec};

/// 表示GF256有限域上的多项式
/// 参见[gf256](crate::gf256)获取更多关于底层域的详情
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial(pub(crate) Vec<GF256>);

impl Polynomial {
    /**
     * 返回多项式的次数
     * 
     * 多项式的次数是指最高非零项的指数。
     * 例如，多项式3x² + 2x + 1的次数为2。
     * 
     * 返回:
     * 多项式的次数
     */
    pub fn degree(&self) -> usize {
        self.0.len() - 1
    }

    /**
     * 在给定点x处计算多项式的值
     * 
     * 使用霍纳法则(Horner's method)高效计算多项式在点x处的值。
     * 霍纳法则减少了乘法运算的次数，通过重写多项式形式来优化计算。
     * 
     * 参数:
     * @param x - 要计算的点
     * 
     * 返回:
     * 多项式在x处的值
     */
    pub fn evaluate(&self, x: &GF256) -> GF256 {
        // Horner's method to evaluate the polynomial at x
        self.0
            .iter()
            .rev()
            .fold(GF256::zero(), |sum, coefficient| &(&sum * x) + coefficient)
    }

    /// 返回零多项式（常数项为0的多项式）
    pub fn zero() -> Self {
        Self(vec![])
    }

    /// 返回单位多项式（常数项为1的多项式）
    pub fn one() -> Self {
        Self(vec![GF256::one()])
    }

    /**
     * 删除多项式末尾的零系数
     * 
     * 用于创建多项式的唯一表示，去除末尾的零系数。
     * 这对于正确比较多项式很重要，因为两个数学上相等的多项式
     * 可能在计算过程中有不同的系数表示。
     * 
     * 返回:
     * 去除末尾零系数后的多项式
     */
    fn strip_trailing_zeros(mut self) -> Self {
        while self.0.last() == Some(&GF256::zero()) {
            self.0.pop();
        }
        self
    }

    /**
     * 返回形如x + constant的一次单位多项式
     * 
     * 创建首项系数为1的一次多项式，常用于插值计算中。
     * 
     * 参数:
     * @param constant - 常数项
     * 
     * 返回:
     * 形如x + constant的多项式
     */
    fn monic_linear(constant: GF256) -> Self {
        Self(vec![constant, GF256::one()])
    }

    /**
     * 根据给定点集创建多项式
     * 
     * 实现Lagrange插值，创建一个多项式p，使得对于所有给定的点(x,y)，
     * 都有p(x) = y。多项式的次数最多为points.len() - 1。
     * 
     * 注意：假设所有x值都是互不相同的，否则函数会panic。
     * 
     * 参数:
     * @param points - 要插值的点集，每个点表示为(x,y)对
     * 
     * 返回:
     * 满足所有点的插值多项式
     */
    pub fn interpolate(points: &[(GF256, GF256)]) -> Self {
        // Lagrangian interpolation, see e.g. https://en.wikipedia.org/wiki/Lagrange_polynomial
        points
            .iter()
            .enumerate()
            .map(|(j, (x_j, y_j))| {
                points
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != j)
                    .map(|(_, (x_i, _))| {
                        (Self::monic_linear(-x_i) / &(x_j - x_i)).expect("Divisor is never zero")
                    })
                    .product::<Polynomial>()
                    * y_j
            })
            .sum()
    }
}

/**
 * 实现多项式的加法操作
 * 
 * 两个多项式相加是将对应位置的系数相加。
 * 如果一个多项式比另一个长，则较短多项式的缺失系数视为零。
 */
impl Add for &Polynomial {
    type Output = Polynomial;

    fn add(self, other: &Polynomial) -> Self::Output {
        Polynomial(
            self.0
                .iter()
                .zip_longest(other.0.iter())
                .map(|p| match p.left_and_right() {
                    (Some(a), Some(b)) => a + b,
                    (Some(a), None) => *a,
                    (None, Some(b)) => *b,
                    _ => unreachable!(),
                })
                .collect(),
        )
        .strip_trailing_zeros()
    }
}

/**
 * 实现多项式的求和聚合
 * 
 * 计算多个多项式的和，从零多项式开始累加。
 */
impl Sum for Polynomial {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Polynomial::zero(), |sum, term| &sum + &term)
    }
}

/**
 * 实现多项式与GF256标量的乘法
 * 
 * 将多项式的每个系数与标量相乘。
 */
impl Mul<&GF256> for Polynomial {
    type Output = Polynomial;

    fn mul(self, s: &GF256) -> Self::Output {
        Polynomial(self.0.into_iter().map(|a| &a * s).collect()).strip_trailing_zeros()
    }
}

/**
 * 实现多项式之间的乘法
 * 
 * 计算两个多项式的乘积，使用卷积公式：
 * (f * g)[i] = Σ f[j] * g[i-j]，其中j的取值范围使f[j]和g[i-j]都存在。
 * 结果多项式的次数是两个输入多项式次数的和。
 */
#[allow(clippy::suspicious_arithmetic_impl)]
impl Mul for &Polynomial {
    type Output = Polynomial;

    fn mul(self, other: &Polynomial) -> Self::Output {
        let degree = self.degree() + other.degree();
        Polynomial(
            (0..=degree)
                .map(|i| {
                    (0..=i)
                        .filter(|j| j <= &self.degree() && i - j <= other.degree())
                        .map(|j| &self.0[j] * &other.0[i - j])
                        .sum()
                })
                .collect(),
        )
    }
}

/**
 * 实现多项式与GF256标量的除法
 * 
 * 将多项式的每个系数除以标量。
 * 如果除数为零，则返回错误。
 */
#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<&GF256> for Polynomial {
    type Output = FastCryptoResult<Polynomial>;

    fn div(self, divisor: &GF256) -> Self::Output {
        let inverse = (&GF256::one() / divisor)?;
        Ok(Polynomial(self.0.iter().map(|a| a * &inverse).collect()).strip_trailing_zeros())
    }
}

/**
 * 实现多项式的乘积聚合
 * 
 * 计算多个多项式的乘积，从单位多项式开始累乘。
 */
impl Product for Polynomial {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |product, factor| &product * &factor)
    }
}

#[cfg(test)]
mod tests {
    use crate::gf256::GF256;
    use crate::polynomial::Polynomial;

    #[test]
    fn test_polynomial_evaluation() {
        let x = GF256::from(2);
        let c = [GF256::from(1), GF256::from(2), GF256::from(3)];
        let result = Polynomial(c.to_vec()).evaluate(&x);
        assert_eq!(
            [
                c[0],
                [c[1], x].into_iter().product(),
                [c[2], x, x].into_iter().product()
            ]
            .into_iter()
            .sum::<GF256>(),
            result
        );
    }

    #[test]
    fn test_arithmetic() {
        let p1 = Polynomial(vec![GF256::from(1), GF256::from(2), GF256::from(3)]);
        let p2 = Polynomial(vec![GF256::from(4), GF256::from(5)]);
        let p3 = Polynomial(vec![GF256::from(2)]);
        assert_eq!(
            &p1 + &p2,
            Polynomial(vec![GF256::from(5), GF256::from(7), GF256::from(3)])
        );
        assert_eq!(
            &p1 * &p3,
            Polynomial(vec![GF256::from(2), GF256::from(4), GF256::from(6)])
        );
    }

    #[test]
    fn test_interpolation() {
        let x = [GF256::from(1), GF256::from(2), GF256::from(3)];
        let y = [GF256::from(7), GF256::from(11), GF256::from(17)];
        let points = x
            .iter()
            .zip(y.iter())
            .map(|(x, y)| (*x, *y))
            .collect::<Vec<_>>();

        let p = Polynomial::interpolate(&points);

        assert!(p.degree() <= points.len());
        for (x, y) in points {
            assert_eq!(y, p.evaluate(&x));
        }
    }
}
