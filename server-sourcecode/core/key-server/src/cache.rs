// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 缓存系统模块
 * 
 * 本模块实现了一个通用的LRU缓存系统，具有以下特点：
 * 1. 基于LRU（最近最少使用）策略进行缓存项淘汰
 * 2. 支持基于时间的自动过期机制（TTL）
 * 3. 线程安全实现，支持并发访问
 * 4. 通用泛型实现，支持任意可哈希键和可复制值
 * 
 * 此缓存系统用于优化服务器性能，减少对外部系统（如GraphQL API）的重复查询。
 */

use crate::externals::current_epoch_time;
use lru::LruCache;
use parking_lot::Mutex;
use std::hash::Hash;
use std::num::NonZero;

/// 缓存大小常量，定义LRU缓存的最大条目数
pub(crate) const CACHE_SIZE: usize = 1000;
/// 缓存TTL常量，定义缓存条目的有效期（毫秒）
pub(crate) const CACHE_TTL: u64 = 3 * 60 * 1000; // 3分钟

/**
 * 缓存条目结构
 * 
 * 封装缓存中存储的值及其过期时间
 * 
 * 字段:
 * @field value - 缓存的实际值
 * @field expiry - 条目过期时间（毫秒时间戳）
 */
struct CacheEntry<V> {
    pub value: V,       // 缓存值
    pub expiry: u64,    // 过期时间戳
}

/**
 * 通用LRU缓存结构
 * 
 * 实现带TTL的线程安全LRU缓存
 * 
 * 字段:
 * @field ttl - 缓存条目的生存时间（毫秒）
 * @field cache - 底层LRU缓存，使用互斥锁保护
 */
pub(crate) struct Cache<K, V> {
    ttl: u64,                                   // 缓存条目生存时间
    cache: Mutex<LruCache<K, CacheEntry<V>>>,   // 线程安全的LRU缓存
}

/**
 * 缓存操作实现
 * 
 * 提供缓存的基本操作，包括创建、获取和插入
 * 约束键(K)为可哈希和相等比较，值(V)为可复制
 */
impl<K: Hash + Eq, V: Copy> Cache<K, V> {
    /**
     * 创建新的缓存实例
     * 
     * 使用指定的TTL和大小创建缓存
     * 
     * 参数:
     * @param ttl - 缓存条目生存时间（毫秒）
     * @param size - 缓存最大条目数
     * 
     * 返回:
     * 新创建的缓存实例
     * 
     * 异常:
     * 如果ttl或size为0，则会触发panic
     */
    pub fn new(ttl: u64, size: usize) -> Self {
        assert!(size > 0 && ttl > 0, "TTL和大小必须大于0");
        Self {
            ttl,
            cache: Mutex::new(LruCache::new(NonZero::new(size).expect("固定值"))),
        }
    }

    /**
     * 获取缓存条目
     * 
     * 尝试获取与指定键关联的值
     * 如果值已过期，则移除并返回None
     * 
     * 参数:
     * @param key - 要查找的键
     * 
     * 返回:
     * 如果键存在且未过期，则返回关联的值，否则返回None
     */
    pub fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.cache.lock();
        match cache.get(key) {
            Some(entry) => {
                if entry.expiry < current_epoch_time() {
                    cache.pop(key);
                    None
                } else {
                    Some(entry.value)
                }
            }
            None => None,
        }
    }

    /**
     * 插入或更新缓存条目
     * 
     * 将键值对插入缓存，如果键已存在则更新值
     * 计算并设置条目的过期时间
     * 
     * 参数:
     * @param key - 要插入的键
     * @param value - 要存储的值
     */
    pub fn insert(&self, key: K, value: V) {
        let mut cache = self.cache.lock();
        cache.put(
            key,
            CacheEntry {
                value,
                expiry: current_epoch_time() + self.ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    /**
     * 测试缓存插入和获取
     * 
     * 验证基本的插入和获取功能是否正常工作
     */
    #[test]
    fn test_cache_insert_and_get() {
        let cache = Cache::new(1000, 10);
        cache.insert(1, "value1");
        assert_eq!(cache.get(&1), Some("value1"));
    }

    /**
     * 测试缓存过期机制
     * 
     * 验证TTL过期机制是否正常工作
     * 插入一个条目，等待超过TTL时间后，该条目应该不可获取
     */
    #[test]
    fn test_cache_expiry() {
        let cache = Cache::new(1000, 10);
        cache.insert(1, "value1");
        sleep(Duration::from_millis(1100));
        assert_eq!(cache.get(&1), None);
    }

    /**
     * 测试缓存覆盖
     * 
     * 验证对同一键多次插入时，值会被更新
     */
    #[test]
    fn test_cache_overwrite() {
        let cache = Cache::new(1000, 10);
        cache.insert(1, "value1");
        cache.insert(1, "value2");
        assert_eq!(cache.get(&1), Some("value2"));
    }

    /**
     * 测试LRU淘汰策略
     * 
     * 验证当缓存达到容量上限时，最近最少使用的条目会被淘汰
     */
    #[test]
    fn test_cache_lru_eviction() {
        let cache = Cache::new(1000, 2);
        cache.insert(1, "value1");
        cache.insert(2, "value2");
        cache.insert(3, "value3");
        assert_eq!(cache.get(&1), None); // 应该被淘汰
        assert_eq!(cache.get(&2), Some("value2"));
        assert_eq!(cache.get(&3), Some("value3"));
    }
}
