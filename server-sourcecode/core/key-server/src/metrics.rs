// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 性能监控指标模块
 * 
 * 本模块实现了密钥服务器的性能监控系统，提供以下功能：
 * 1. 请求计数器 - 记录不同类型的请求总数
 * 2. 错误计数器 - 按类型记录内部错误次数
 * 3. 时间延迟直方图 - 测量关键操作的执行时间
 * 4. 请求状态监控 - 跟踪外部API调用的成功/失败率
 * 
 * 所有指标均可通过Prometheus监控系统查询，便于服务质量监控。
 */

use prometheus::{
    register_histogram_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, Histogram, IntCounter, IntCounterVec, Registry,
};
use std::time::Instant;

/**
 * 指标结构体
 * 
 * 包含服务器运行过程中收集的所有度量指标
 * 这些指标用于监控服务器性能和健康状态
 */
#[derive(Debug)]
pub(crate) struct Metrics {
    /// 接收的请求总数
    pub requests: IntCounter,

    /// 接收的服务请求总数
    pub service_requests: IntCounter,

    /// 按类型划分的内部错误总数
    errors: IntCounterVec,

    /// 最新检查点时间戳的延迟
    pub checkpoint_timestamp_delay: Histogram,

    /// 获取最新检查点时间戳的持续时间
    pub get_checkpoint_timestamp_duration: Histogram,

    /// 获取最新检查点时间戳请求的状态
    pub get_checkpoint_timestamp_status: IntCounterVec,

    /// 获取参考gas价格请求的状态
    pub get_reference_gas_price_status: IntCounterVec,

    /// check_policy操作的持续时间
    pub check_policy_duration: Histogram,

    /// fetch_pkg_ids操作的持续时间
    pub fetch_pkg_ids_duration: Histogram,

    /// 按ID数量划分的请求总数
    pub requests_per_number_of_ids: Histogram,
}

impl Metrics {
    /**
     * 创建新的指标实例
     * 
     * 在指定的Prometheus注册表中注册所有监控指标
     * 
     * 参数:
     * @param registry - Prometheus注册表
     * 
     * 返回:
     * 初始化的Metrics实例
     */
    pub(crate) fn new(registry: &Registry) -> Self {
        Self {
            requests: register_int_counter_with_registry!(
                "total_requests",
                "获取密钥请求的总数",
                registry
            )
            .unwrap(),
            errors: register_int_counter_vec_with_registry!(
                "internal_errors",
                "按类型划分的内部错误总数",
                &["internal_error_type"],
                registry
            )
            .unwrap(),
            service_requests: register_int_counter_with_registry!(
                "service_requests",
                "服务请求的总数",
                registry
            )
            .unwrap(),
            checkpoint_timestamp_delay: register_histogram_with_registry!(
                "checkpoint_timestamp_delay",
                "最新检查点时间戳的延迟",
                default_external_call_duration_buckets(),
                registry
            )
            .unwrap(),
            get_checkpoint_timestamp_duration: register_histogram_with_registry!(
                "checkpoint_timestamp_duration",
                "获取最新检查点时间戳的持续时间",
                default_external_call_duration_buckets(),
                registry
            )
            .unwrap(),
            get_checkpoint_timestamp_status: register_int_counter_vec_with_registry!(
                "checkpoint_timestamp_status",
                "获取最新时间戳请求的状态",
                &["status"],
                registry,
            )
            .unwrap(),
            fetch_pkg_ids_duration: register_histogram_with_registry!(
                "fetch_pkg_ids_duration",
                "fetch_pkg_ids操作的持续时间",
                default_fast_call_duration_buckets(),
                registry
            )
            .unwrap(),
            check_policy_duration: register_histogram_with_registry!(
                "check_policy_duration",
                "check_policy操作的持续时间",
                default_fast_call_duration_buckets(),
                registry
            )
            .unwrap(),
            get_reference_gas_price_status: register_int_counter_vec_with_registry!(
                "get_reference_gas_price_status",
                "获取参考gas价格请求的状态",
                &["status"],
                registry
            )
            .unwrap(),
            requests_per_number_of_ids: register_histogram_with_registry!(
                "requests_per_number_of_ids",
                "按ID数量划分的请求总数",
                buckets(0.0, 5.0, 1.0),
                registry
            )
            .unwrap(),
        }
    }

    /**
     * 记录错误事件
     * 
     * 增加指定类型错误的计数器
     * 
     * 参数:
     * @param error_type - 错误类型标识符
     */
    pub(crate) fn observe_error(&self, error_type: &str) {
        self.errors.with_label_values(&[error_type]).inc();
    }
}

/**
 * 测量闭包执行时间
 * 
 * 如果指定了直方图，则测量闭包执行时间并记录
 * 否则仅执行闭包
 * 
 * 参数:
 * @param metrics - 可选的直方图指标
 * @param closure - 要执行和测量的闭包
 * 
 * 返回:
 * 闭包的返回值
 */
pub(crate) fn call_with_duration<T>(metrics: Option<&Histogram>, closure: impl FnOnce() -> T) -> T {
    if let Some(metrics) = metrics {
        let start = Instant::now();
        let result = closure();
        metrics.observe(start.elapsed().as_millis() as f64);
        result
    } else {
        closure()
    }
}

/**
 * 创建观察回调函数
 * 
 * 返回一个闭包，该闭包将输入通过转换函数处理后记录到直方图
 * 
 * 参数:
 * @param histogram - 要更新的直方图
 * @param f - 将输入值转换为f64的函数
 * 
 * 返回:
 * 接受T类型输入并更新直方图的闭包
 */
pub(crate) fn observation_callback<T>(histogram: &Histogram, f: impl Fn(T) -> f64) -> impl Fn(T) {
    let histogram = histogram.clone();
    move |t| {
        histogram.observe(f(t));
    }
}

/**
 * 创建状态回调函数
 * 
 * 返回一个闭包，该闭包根据布尔状态更新计数器向量
 * 
 * 参数:
 * @param metrics - 要更新的计数器向量
 * 
 * 返回:
 * 接受布尔状态并更新相应计数器的闭包
 */
pub(crate) fn status_callback(metrics: &IntCounterVec) -> impl Fn(bool) {
    let metrics = metrics.clone();
    move |status: bool| {
        let value = match status {
            true => "success",
            false => "failure",
        };
        metrics.with_label_values(&[value]).inc();
    }
}

/**
 * 创建等距分布的桶值
 * 
 * 生成从起始值到结束值按步长均匀分布的桶值数组
 * 用于创建直方图的桶配置
 * 
 * 参数:
 * @param start - 起始值
 * @param end - 结束值
 * @param step - 步长
 * 
 * 返回:
 * 桶值数组
 */
fn buckets(start: f64, end: f64, step: f64) -> Vec<f64> {
    let mut buckets = vec![];
    let mut current = start;
    while current < end {
        buckets.push(current);
        current += step;
    }
    buckets.push(end);
    buckets
}

/**
 * 默认外部调用持续时间桶
 * 
 * 为外部API调用定义的默认桶配置
 * 范围从50ms到2000ms，步长为50ms
 * 
 * 返回:
 * 适用于外部调用的桶值数组
 */
fn default_external_call_duration_buckets() -> Vec<f64> {
    buckets(50.0, 2000.0, 50.0)
}

/**
 * 默认快速调用持续时间桶
 * 
 * 为内部快速操作定义的默认桶配置
 * 范围从10ms到100ms，步长为10ms
 * 
 * 返回:
 * 适用于快速调用的桶值数组
 */
fn default_fast_call_duration_buckets() -> Vec<f64> {
    buckets(10.0, 100.0, 10.0)
}
