// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * GF(256)上多项式运算模块
 * 
 * 本模块实现了在GF(256)有限域上的多项式表示和操作，
 * 主要用于实现Shamir秘密共享和拉格朗日插值等密码学应用。
 * 这些操作是阈值加密系统的基础，允许在不泄露原始秘密的情况下，
 * 将秘密分割为多个份额，并在获得足够份额后重建。
 * 
 * 主要功能:
 * - 多项式表示与基本运算（加法、乘法、缩放）
 * - 拉格朗日插值算法实现
 * - 多项式求值
 */
module seal::polynomial;

use seal::gf256;

/**
 * GF(256)上的多项式
 * 
 * coefficients数组存储多项式的系数，
 * 第一个元素为常数项，后续元素分别为一次项、二次项等系数。
 * 例如：多项式 3 + 5x + 2x² 表示为 [3, 5, 2]
 */
public struct Polynomial has copy, drop, store {
    coefficients: vector<u8>,
}

/**
 * 获取多项式的常数项
 * 
 * 常数项是多项式系数数组的第一个元素，
 * 在密钥共享中，它通常代表被共享的秘密值。
 * 
 * 参数:
 * @param p - 多项式
 * 
 * 返回:
 * 多项式的常数项，如果多项式为空则返回0
 */
public(package) fun get_constant_term(p: &Polynomial): u8 {
    if (p.coefficients.is_empty()) {
        return 0
    };
    p.coefficients[0]
}

/**
 * 计算两个多项式的和
 * 
 * 在GF(256)上逐项进行加法运算（异或操作）
 * 
 * 参数:
 * @param x - 第一个多项式
 * @param y - 第二个多项式
 * 
 * 返回:
 * 相加后的多项式
 */
fun add(x: &Polynomial, y: &Polynomial): Polynomial {
    let x_length: u64 = x.coefficients.length();
    let y_length: u64 = y.coefficients.length();
    if (x_length < y_length) {
        // 确保x是长度较大的多项式，简化处理逻辑
        return add(y, x)
    };
    let mut coefficients: vector<u8> = vector::empty<u8>();
    // 对重叠部分进行系数加法
    y_length.do!(|i| coefficients.push_back(gf256::add(x.coefficients[i], y.coefficients[i])));
    // 复制x中剩余的高阶项
    (x_length - y_length).do!(|i| coefficients.push_back(x.coefficients[i + y_length]));
    let result = Polynomial { coefficients };
    reduce(result);
    result
}

/**
 * 获取多项式的次数
 * 
 * 次数是最高非零系数的指数
 * 
 * 参数:
 * @param x - 多项式
 * 
 * 返回:
 * 多项式的次数
 */
public(package) fun degree(x: &Polynomial): u64 {
    x.coefficients.length() - 1
}

/**
 * 约简多项式
 * 
 * 移除多项式末尾的零系数，确保多项式表示的规范性
 * 
 * 参数:
 * @param x - 需要约简的多项式
 */
fun reduce(mut x: Polynomial) {
    while (x.coefficients[x.coefficients.length() - 1] == 0) {
        x.coefficients.pop_back();
    };
}

/**
 * 计算两个多项式的乘积
 * 
 * 使用标准的多项式乘法算法，在GF(256)域上进行运算
 * 
 * 参数:
 * @param x - 第一个多项式
 * @param y - 第二个多项式
 * 
 * 返回:
 * 相乘后的多项式
 */
fun mul(x: &Polynomial, y: &Polynomial): Polynomial {
    let degree = x.degree() + y.degree();

    // 计算所有系数项
    let coefficients = vector::tabulate!(degree + 1, |i| {
        let mut sum = 0;
        i.do_eq!(|j| {
            if (j <= x.degree() && i - j <= y.degree()) {
                sum = gf256::add(sum, gf256::mul(x.coefficients[j], y.coefficients[i - j]));
            }
        });
        sum
    });
    let result = Polynomial { coefficients };
    reduce(result);
    result
}

/**
 * 将多项式除以标量
 * 
 * 在GF(256)上，将多项式的每个系数除以给定的标量值
 * 
 * 参数:
 * @param x - 多项式
 * @param s - 标量除数
 * 
 * 返回:
 * 除法结果
 */
fun div(x: &Polynomial, s: u8): Polynomial {
    scale(x, gf256::div(1, s))
}

/**
 * 将多项式乘以标量
 * 
 * 在GF(256)上，将多项式的每个系数乘以给定的标量值
 * 
 * 参数:
 * @param x - 多项式
 * @param s - 标量乘数
 * 
 * 返回:
 * 缩放后的多项式
 */
fun scale(x: &Polynomial, s: u8): Polynomial {
    Polynomial { coefficients: x.coefficients.map_ref!(|c| gf256::mul(*c, s)) }
}

/**
 * 创建形如 (x - c) 的一次多项式
 * 
 * 生成系数为[-c, 1]的一次多项式，常用于拉格朗日插值
 * 
 * 参数:
 * @param c - 常数c
 * 
 * 返回:
 * 形如 (x - c) 的一次多项式
 */
fun monic_linear(c: &u8): Polynomial {
    Polynomial { coefficients: vector[gf256::sub(0, *c), 1] }
}

/**
 * 拉格朗日插值
 * 
 * 根据给定的点集 (x[i], y[i]) 构造一个多项式，使得该多项式通过所有给定点。
 * 这是秘密重建阶段的核心算法，允许从足够数量的份额中重建秘密。
 * 
 * 参数:
 * @param x - x坐标值数组
 * @param y - y坐标值数组
 * 
 * 返回:
 * 通过所有点的插值多项式
 */
public(package) fun interpolate(x: &vector<u8>, y: &vector<u8>): Polynomial {
    assert!(x.length() == y.length());
    let n = x.length();
    let mut sum = Polynomial { coefficients: vector::empty<u8>() };
    n.do!(|j| {
        let mut product = Polynomial { coefficients: vector[1] };
        n.do!(|i| {
            if (i != j) {
                product =
                    mul(
                        &product,
                        &div(&monic_linear(&x[i]), gf256::sub(x[j], x[i])),
                    );
            };
        });
        sum = add(&sum, &scale(&product, y[j]));
    });
    sum
}

/**
 * 多项式求值
 * 
 * 计算多项式在给定点x处的值
 * 使用Horner方法进行高效求值
 * 
 * 参数:
 * @param p - 多项式
 * @param x - 求值点
 * 
 * 返回:
 * 多项式在点x处的值
 */
public fun evaluate(p: &Polynomial, x: u8): u8 {
    let mut result = 0;
    let n = p.coefficients.length();
    n.do!(|i| {
        result = gf256::add(gf256::mul(result, x), p.coefficients[n - i - 1]);
    });
    result
}

/**
 * 测试多项式算术运算
 * 
 * 验证多项式加法和乘法运算的正确性
 */
#[test]
fun test_arithmetic() {
    let x = Polynomial { coefficients: vector[1, 2, 3] };
    let y = Polynomial { coefficients: vector[4, 5] };
    let z = Polynomial { coefficients: vector[2] };
    assert!(x.add(&y).coefficients == vector[5, 7, 3]);
    assert!(x.mul(&z).coefficients == vector[2, 4, 6]);
    assert!(x.mul(&y).coefficients == x"040d060f");
}

/**
 * 测试拉格朗日插值
 * 
 * 验证插值算法能否正确构造通过给定点集的多项式
 */
#[test]
fun test_interpolate() {
    let x = vector[1, 2, 3];
    let y = vector[7, 11, 17];
    let p = interpolate(&x, &y);
    assert!(p.coefficients == x"1d150f");
    // 验证插值多项式通过所有给定点
    x.zip_do!(y, |x, y| assert!(p.evaluate(x) == y));
}
