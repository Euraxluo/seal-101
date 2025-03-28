/**
 * 游戏加密操作
 */
import { SealClient, SessionKey } from '@mysten/seal';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { fromB64 } from '@mysten/sui/utils';
import { Card, CardType, EncryptedCard } from './models';
import { constructTxBytes } from './game-utils';
import { CardError, CryptoGameError, NetworkError, PermissionError, SessionError } from './errors';

// 简单的会话密钥缓存
const sessionKeyCache = new Map<string, {
  key: SessionKey,
  expiryTime: number
}>();

// 性能监控统计
const perfStats = {
  decryptCount: 0,
  totalDecryptTime: 0,
  maxDecryptTime: 0,
  minDecryptTime: Number.MAX_SAFE_INTEGER,
  lastReportTime: Date.now()
};

/**
 * 从Base64私钥创建Ed25519密钥对
 * 用于后续创建SessionKey和加密操作的身份验证
 * 参考Seal SDK中SessionKey需要的signer参数
 * 
 * @param privateKeyBase64 Base64格式的私钥
 * @returns Ed25519密钥对
 * @throws Error 如果创建密钥对失败
 */
export function createKeypairFromBase64(privateKeyBase64: string): Ed25519Keypair {
  try {
    return Ed25519Keypair.fromSecretKey(fromB64(privateKeyBase64));
  } catch (error) {
    console.error('创建密钥对失败:', error);
    throw new Error(`创建密钥对失败: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * 创建会话密钥
 * 实现参考Seal SDK中SessionKey的构造方式：
 * - address: 用户的Sui地址，验证解密权限
 * - packageId: 包ID，与加密时使用的packageId对应
 * - ttlMin: 会话有效期（分钟）
 * - signer: 用于签名会话请求的密钥对
 * 
 * @param address 地址
 * @param packageId 包ID
 * @param keypair 密钥对
 * @param ttlMin 有效期（分钟）
 * @returns 会话密钥
 */
export async function createSessionKey(
  address: string,
  packageId: string,
  keypair: Ed25519Keypair,
  ttlMin: number = 10
): Promise<SessionKey> {
  try {
    return new SessionKey({
      address,
      packageId,
      ttlMin,
      signer: keypair
    });
  } catch (error) {
    console.error('创建会话密钥失败:', error);
    throw new SessionError(`创建会话密钥失败: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * 计算会话密钥提前过期时间
 * 根据总有效期动态调整提前量，有效期越长，提前量越大
 * 
 * @param ttlMin 总有效期（分钟）
 * @returns 提前过期的毫秒数
 */
function calculateEarlyExpiryBuffer(ttlMin: number): number {
  // 基础提前量为5分钟
  const baseBuffer = 5 * 60 * 1000;
  
  // 对于较长的会话（超过30分钟），提前量为总时间的15%
  if (ttlMin > 30) {
    return Math.max(baseBuffer, ttlMin * 60 * 1000 * 0.15);
  }
  
  // 对于较短的会话，固定提前5分钟
  return baseBuffer;
}

/**
 * 获取或创建会话密钥，带缓存功能
 * 优先从缓存中获取，如缓存不存在或已过期则创建新的会话密钥
 * 实现了动态过期时间计算和自动更新机制
 * 
 * @param address 地址
 * @param packageId 包ID
 * @param keypair 密钥对
 * @param ttlMin 有效期（分钟）
 * @param forceRefresh 强制刷新标志
 * @returns 会话密钥
 */
export async function getOrCreateSessionKey(
  address: string,
  packageId: string,
  keypair: Ed25519Keypair,
  ttlMin: number = 10,
  forceRefresh: boolean = false
): Promise<SessionKey> {
  const cacheKey = `${address}:${packageId}`;
  const now = Date.now();
  
  // 检查缓存
  const cached = sessionKeyCache.get(cacheKey);
  
  // 检查是否有效（考虑到提前过期）
  if (!forceRefresh && cached && now < cached.expiryTime) {
    // 如果过期时间接近（在15秒内），在后台刷新令牌并继续使用当前令牌
    if (cached.expiryTime - now < 15000) {
      // 在后台异步刷新会话
      setTimeout(async () => {
        try {
          const newSessionKey = await createSessionKey(address, packageId, keypair, ttlMin);
          const earlyExpiryBuffer = calculateEarlyExpiryBuffer(ttlMin);
          const newExpiryTime = now + (ttlMin * 60 * 1000) - earlyExpiryBuffer;
          
          sessionKeyCache.set(cacheKey, {
            key: newSessionKey,
            expiryTime: newExpiryTime
          });
          console.log('会话密钥在后台静默更新成功');
        } catch (error) {
          console.error('后台刷新会话密钥失败:', error);
          // 失败不阻塞当前流程
        }
      }, 0);
    }
    
    console.log('使用缓存的会话密钥');
    return cached.key;
  }
  
  // 创建新的会话密钥
  console.log('创建新的会话密钥');
  const sessionKey = await createSessionKey(address, packageId, keypair, ttlMin);
  
  // 动态计算提前过期时间
  const earlyExpiryBuffer = calculateEarlyExpiryBuffer(ttlMin);
  const expiryTime = now + (ttlMin * 60 * 1000) - earlyExpiryBuffer;
  
  // 存入缓存
  sessionKeyCache.set(cacheKey, {
    key: sessionKey,
    expiryTime
  });
  
  return sessionKey;
}

/**
 * 清除过期的会话密钥缓存
 * 可以定期调用此函数来维护缓存
 * 
 * @returns 清除的缓存条目数量
 */
export function cleanExpiredSessionKeys(): number {
  const now = Date.now();
  let cleanCount = 0;
  
  for (const [key, value] of sessionKeyCache.entries()) {
    if (now >= value.expiryTime) {
      sessionKeyCache.delete(key);
      cleanCount++;
    }
  }
  
  return cleanCount;
}

/**
 * 重试指定操作
 * 在网络错误等临时性故障时进行自动重试
 * 
 * @param operation 要重试的操作函数
 * @param maxRetries 最大重试次数
 * @param delayMs 重试间隔(毫秒)
 * @returns 操作结果
 */
async function retryOperation<T>(
  operation: () => Promise<T>, 
  maxRetries: number = 3,
  delayMs: number = 1000
): Promise<T> {
  let lastError: any;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error: any) {
      lastError = error;
      
      // 判断是否是可重试的错误类型
      const isRetryable = 
        error instanceof NetworkError || 
        (error.message && (
          error.message.includes('timeout') || 
          error.message.includes('network') ||
          error.message.includes('connection')
        ));
      
      if (!isRetryable || attempt >= maxRetries) {
        break;
      }
      
      console.warn(`操作失败，${attempt < maxRetries ? '将在' + delayMs + 'ms后重试' : '已达到最大重试次数'}:`, error);
      
      // 等待一段时间后重试，每次重试增加延迟
      await new Promise(resolve => setTimeout(resolve, delayMs * attempt));
    }
  }
  
  throw lastError;
}

/**
 * 记录性能统计
 * 
 * @param opName 操作名称
 * @param duration 持续时间(毫秒)
 */
function recordPerformanceStat(opName: string, duration: number): void {
  if (opName === 'decrypt') {
    perfStats.decryptCount++;
    perfStats.totalDecryptTime += duration;
    perfStats.maxDecryptTime = Math.max(perfStats.maxDecryptTime, duration);
    perfStats.minDecryptTime = Math.min(perfStats.minDecryptTime, duration);
    
    // 每100次操作或每10分钟输出一次统计信息
    const now = Date.now();
    if (perfStats.decryptCount % 100 === 0 || (now - perfStats.lastReportTime) > 600000) {
      const avgTime = perfStats.totalDecryptTime / perfStats.decryptCount;
      console.info(`性能统计 - 解密：共${perfStats.decryptCount}次，平均${avgTime.toFixed(2)}ms，` +
                  `最短${perfStats.minDecryptTime}ms，最长${perfStats.maxDecryptTime}ms`);
      perfStats.lastReportTime = now;
    }
  }
}

/**
 * 解密卡牌
 * 使用Seal的门限解密功能解密卡牌数据
 * 流程参考Seal SDK中的decrypt方法：
 * 1. 构建txBytes交易字节（用于验证权限）
 * 2. 调用sealClient.decrypt进行解密
 * 3. 将解密后的数据转换回Card对象
 * 
 * 底层实现：
 * - SealClient.decrypt方法会调用EncryptedObject.parse解析加密数据
 * - 会验证密钥服务器配置和阈值要求
 * - 通过SessionKey获取证书和请求参数
 * - 从多个密钥服务器获取密钥分片，直到达到阈值数量
 * - 最后组合这些分片解密数据
 * 
 * @param sealClient Seal客户端
 * @param suiClient Sui客户端
 * @param encryptedCard 加密卡牌
 * @param sessionKey 会话密钥
 * @param packageId 包ID
 * @param moduleName 模块名
 * @param isOfflineMode 是否处于离线模式
 * @returns 解密后的卡牌
 */
export async function decryptCard(
  sealClient: SealClient,
  suiClient: SuiClient,
  encryptedCard: EncryptedCard,
  sessionKey: SessionKey,
  packageId: string,
  moduleName: string = 'seal',
  isOfflineMode: boolean = false
): Promise<Card> {
  const startTime = Date.now();
  
  try {
    // 验证加密卡牌的有效性
    if (!encryptedCard.innerIds) {
      throw new CardError('无效的加密卡牌格式，缺少innerIds');
    }

    // 离线模式处理
    if (isOfflineMode || encryptedCard.ptbId === 'offline-mode') {
      console.log('使用离线模式解密...');
      try {
        // 在离线模式中，加密数据实际上是JSON字符串的字节表示
        const cardJson = new TextDecoder().decode(encryptedCard.encryptedData);
        return JSON.parse(cardJson) as Card;
      } catch (error) {
        console.error('离线模式解密失败:', error);
        throw new CardError(`离线模式解密失败: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    
    // 在线模式：使用门限解密并加入重试机制
    return await retryOperation(async () => {
      // 构建交易字节
      let txBytes: Uint8Array;
      try {
        txBytes = await constructTxBytes(
          packageId,
          moduleName,
          suiClient,
          encryptedCard.innerIds
        );
      } catch (error) {
        console.error('构建交易字节失败:', error);
        throw new NetworkError('与区块链通信失败，无法构建交易');
      }
      
      // 使用SEAL解密
      try {
        const decryptedResult = await sealClient.decrypt({
          data: encryptedCard.encryptedData,
          sessionKey,
          txBytes
        });
        
        // 解析解密后的卡牌数据
        const cardJson = new TextDecoder().decode(decryptedResult);
        return JSON.parse(cardJson) as Card;
      } catch (error: any) {
        // 解析Seal SDK的错误
        if (error.message?.includes('无权访问') || 
            error.message?.includes('access') || 
            error.message?.includes('permission')) {
          throw new PermissionError('没有权限解密此卡牌');
        }
        
        if (error.message?.includes('session') || 
            error.message?.includes('expired')) {
          throw new SessionError('会话已过期，请重新创建会话');
        }
        
        if (error.message?.includes('network') || 
            error.message?.includes('timeout') ||
            error.message?.includes('connection')) {
          throw new NetworkError('与密钥服务器通信失败');
        }
        
        // 其他错误
        throw new CardError(`解密卡牌失败: ${error.message}`);
      }
    }, 3, 1000);
  } catch (error) {
    // 记录错误
    if (error instanceof CryptoGameError) {
      console.error(`[${error.name}] ${error.message}`);
      throw error;
    } else {
      console.error('解密卡牌时发生未知错误:', error);
      throw new CardError('解密卡牌时发生未知错误');
    }
  } finally {
    // 记录性能统计
    const duration = Date.now() - startTime;
    recordPerformanceStat('decrypt', duration);
  }
}

/**
 * 查看牌组顶部卡牌（预知未来功能）
 * 使用Seal解密功能预览牌组顶部的几张卡牌
 * 此功能展示了如何在不修改游戏状态的情况下使用Seal解密能力
 * 添加了并行解密和性能监控功能
 * 
 * @param sealClient Seal客户端
 * @param suiClient Sui客户端
 * @param deck 牌组
 * @param sessionKey 会话密钥
 * @param packageId 包ID
 * @param moduleName 模块名
 * @param count 要查看的卡牌数量
 * @param isOfflineMode 是否处于离线模式
 * @returns 牌组顶部的卡牌
 */
export async function viewTopCards(
  sealClient: SealClient,
  suiClient: SuiClient,
  deck: EncryptedCard[],
  sessionKey: SessionKey,
  packageId: string,
  moduleName: string = 'seal',
  count: number = 3,
  isOfflineMode: boolean = false
): Promise<Card[]> {
  try {
    const startTime = Date.now();
    
    // 获取牌组顶部的卡牌
    const topCards = deck.slice(0, Math.min(count, deck.length));
    
    // 并行解密每张卡牌，传递离线模式参数
    const decryptPromises = topCards.map(card => 
      decryptCard(sealClient, suiClient, card, sessionKey, packageId, moduleName, isOfflineMode)
    );
    
    // 等待所有解密操作完成
    const decryptedCards = await Promise.all(decryptPromises);
    
    // 记录整体性能
    const duration = Date.now() - startTime;
    console.info(`并行解密${decryptedCards.length}张卡牌共耗时${duration}ms，平均每张${(duration/decryptedCards.length).toFixed(2)}ms`);
    
    return decryptedCards;
  } catch (error) {
    console.error('查看牌组顶部卡牌失败:', error);
    throw error;
  }
}