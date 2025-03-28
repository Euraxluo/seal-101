/**
 * 卡牌游戏工具函数
 */
import { Card, CardType, EncryptedCard, GameState, Player, GameLog } from './models';
import { SealClient } from '@mysten/seal';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { fromHex } from '@mysten/sui/utils';

// 缓存规范化后的密钥服务器ID
const normalizedServerIdsCache = new Map<string, string>();

/**
 * 生成随机ID
 * @returns 随机字符串ID
 */
export function generateId(): string {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

/**
 * 生成初始牌组
 * @param seed 随机种子，用于确定性测试
 * @returns 初始牌组
 */
export function generateInitialDeck(seed?: string): Card[] {
  const deck: Card[] = [];

  // 添加普通牌 (1-10, 每个数字4张)
  for (let value = 1; value <= 10; value++) {
    for (let i = 0; i < 4; i++) {
      deck.push({
        id: generateId(),
        type: CardType.NORMAL,
        value,
      });
    }
  }

  // 添加特殊牌
  // 3张炸弹
  for (let i = 0; i < 3; i++) {
    deck.push({
      id: generateId(),
      type: CardType.BOMB,
      value: 0,
    });
  }

  // 2张洗牌
  for (let i = 0; i < 2; i++) {
    deck.push({
      id: generateId(),
      type: CardType.SHUFFLE,
      value: 0,
    });
  }

  // 2张预知未来
  for (let i = 0; i < 2; i++) {
    deck.push({
      id: generateId(),
      type: CardType.FUTURE_SIGHT,
      value: 0,
    });
  }

  // 5张拆弹牌
  for (let i = 0; i < 5; i++) {
    deck.push({
      id: generateId(),
      type: CardType.DEFUSE,
      value: 0,
    });
  }

  // 如果提供了种子，则使用伪随机方式洗牌，保证测试的确定性
  if (seed) {
    return deterministicShuffleDeck(deck, seed);
  }

  return deck;
}

/**
 * 洗牌函数
 * @param deck 牌组
 * @returns 打乱后的牌组
 */
export function shuffleDeck<T>(deck: T[]): T[] {
  const shuffled = [...deck];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

/**
 * 确定性洗牌函数（用于测试）
 * @param deck 牌组
 * @param seed 随机种子
 * @returns 打乱后的牌组
 */
export function deterministicShuffleDeck<T>(deck: T[], seed: string): T[] {
  const shuffled = [...deck];
  
  // 基于种子创建一个伪随机数生成器
  const seedRandom = (seed: string, n: number): number => {
    // 简单的伪随机数生成器，确保同一个种子和n总是返回相同的值
    let hash = 0;
    for (let i = 0; i < seed.length; i++) {
      hash = ((hash << 5) - hash) + seed.charCodeAt(i) + n;
      hash |= 0; // 转为32位整数
    }
    // 将hash映射到0-1之间
    return Math.abs((hash / 0x7fffffff) % 1);
  };

  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(seedRandom(seed, i) * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  
  return shuffled;
}

/**
 * 抽取一张牌
 * @param deck 牌组
 * @returns [抽取的牌, 剩余牌组]
 */
export function drawCard<T>(deck: T[]): [T | undefined, T[]] {
  if (deck.length === 0) return [undefined, []];
  
  const [card, ...remainingDeck] = deck;
  return [card, remainingDeck];
}

/**
 * 规范化服务器ID
 * 确保所有ID格式一致，避免多次转换
 * 
 * @param id 原始ID
 * @returns 规范化后的ID
 */
export function normalizeServerId(id: string): string {
  // 检查缓存
  if (normalizedServerIdsCache.has(id)) {
    return normalizedServerIdsCache.get(id)!;
  }
  
  let normalizedId = id;
  // 如果不是0x开头的十六进制，则转换
  if (!id.startsWith('0x')) {
    normalizedId = '0x' + Buffer.from(id).toString('hex');
  }
  
  // 存入缓存
  normalizedServerIdsCache.set(id, normalizedId);
  return normalizedId;
}

/**
 * 规范化服务器ID列表
 * 批量处理多个ID
 * 
 * @param ids 原始ID列表
 * @returns 规范化后的ID列表
 */
export function normalizeServerIds(ids: string[]): string[] {
  return ids.map(id => normalizeServerId(id));
}

/**
 * 根据负载均衡策略选择密钥服务器
 * 使用随机抽样方式选择服务器，避免固定使用相同顺序的服务器
 * 
 * @param availableServerIds 可用服务器ID列表
 * @param threshold 所需的最小服务器数量
 * @returns 选择的服务器ID列表
 */
export function selectKeyServers(
  availableServerIds: string[],
  threshold: number
): string[] {
  // 如果可用服务器数量等于或小于阈值，则返回所有服务器
  if (availableServerIds.length <= threshold) {
    return [...availableServerIds];
  }
  
  // 复制数组避免修改原数组
  const shuffled = [...availableServerIds];
  
  // 随机打乱服务器顺序
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  
  // 返回前threshold+1个服务器（多选1个作为备用）
  return shuffled.slice(0, Math.min(threshold + 1, shuffled.length));
}

/**
 * 批量加密多个卡牌
 * 通过分组并行处理，提高加密效率
 * 
 * @param sealClient Seal客户端
 * @param cards 卡牌列表
 * @param packageId 包ID
 * @param threshold 阈值
 * @param serverObjectIds 服务器对象ID列表
 * @param batchSize 批处理大小
 * @returns 加密后的卡牌列表
 */
async function batchEncryptCards(
  sealClient: SealClient,
  cards: Card[],
  packageId: string,
  threshold: number,
  serverObjectIds: string[],
  batchSize: number = 10
): Promise<EncryptedCard[]> {
  const results: EncryptedCard[] = [];
  
  // 规范化服务器ID
  const normalizedServerIds = normalizeServerIds(serverObjectIds);
  
  // 根据负载均衡策略选择服务器
  const selectedServerIds = selectKeyServers(normalizedServerIds, threshold);
  
  // 分批处理
  for (let i = 0; i < cards.length; i += batchSize) {
    const batch = cards.slice(i, i + batchSize);
    
    // 并行处理当前批次
    const batchPromises = batch.map(async (card) => {
      const cardData = new TextEncoder().encode(JSON.stringify(card));
      
      // 使用Seal加密
      const encryptedResult = await sealClient.encrypt({
        threshold,
        packageId,
        id: `card-${card.id}`,
        data: cardData
      });
      
      return {
        id: card.id,
        encryptedData: encryptedResult.encryptedObject,
        threshold: threshold,
        innerIds: selectedServerIds,
        ptbId: undefined
      } as EncryptedCard;
    });
    
    // 等待当前批次完成
    const batchResults = await Promise.all(batchPromises);
    results.push(...batchResults);
    
    // 添加进度日志
    console.log(`已加密 ${results.length}/${cards.length} 张卡牌`);
  }
  
  return results;
}

/**
 * 使用Seal加密牌组
 * 改进版本：添加批量处理和服务器负载均衡
 * 
 * @param sealClient Seal客户端
 * @param deck 牌组
 * @param packageId 包ID
 * @param threshold 阈值
 * @param serverObjectIds 服务器对象ID列表
 * @param batchSize 批处理大小
 * @returns 加密后的牌组
 */
export async function encryptDeck(
  sealClient: SealClient, 
  deck: Card[], 
  packageId: string,
  threshold: number = 2,
  serverObjectIds: string[] = [],
  batchSize: number = 10
): Promise<EncryptedCard[]> {
  // 记录开始时间
  const startTime = Date.now();
  
  // 使用批量加密
  const encryptedCards = await batchEncryptCards(
    sealClient,
    deck,
    packageId,
    threshold,
    serverObjectIds,
    batchSize
  );
  
  // 记录性能统计
  const duration = Date.now() - startTime;
  const avgTime = duration / encryptedCards.length;
  console.info(`牌组加密完成：${encryptedCards.length}张卡牌，总耗时${duration}ms，平均每张${avgTime.toFixed(2)}ms`);
  
  return encryptedCards;
}

/**
 * 根据服务器对象ID列表初始化Seal客户端
 * 对应Seal SDK中SealClient的初始化方式：
 * - suiClient: 用于与Sui链交互
 * - serverObjectIds: 密钥服务器对象ID列表，用于分布式密钥管理
 * 
 * 注意：在Seal SDK的实现中，serverObjectIds是SealClient的私有成员(#serverObjectIds)，
 * 无法直接访问，但在初始化时必须提供。我们需要在游戏状态中维护这个列表用于后续操作。
 * SealClient会在内部验证这些服务器的有效性，并用于加密和解密过程。
 * 
 * @param suiClient Sui客户端
 * @param serverObjectIds 服务器对象ID列表
 * @returns Seal客户端
 */
export function initializeSealClient(
  suiClient: SuiClient,
  serverObjectIds: string[]
): SealClient {
  return new SealClient({
    suiClient,
    serverObjectIds
  });
}

/**
 * 构建交易字节
 * 用于创建Seal解密所需的交易字节(txBytes)
 * 优化了ID处理逻辑，使用缓存的规范化ID
 * 
 * @param packageId 包ID
 * @param moduleName 模块名称
 * @param suiClient Sui客户端
 * @param innerIds 内部ID列表
 * @returns 交易字节
 */
export async function constructTxBytes(
  packageId: string,
  moduleName: string,
  suiClient: SuiClient,
  innerIds: string[],
): Promise<Uint8Array> {
  const tx = new Transaction();
  
  // 使用规范化后的ID列表
  const normalizedIds = normalizeServerIds(innerIds);
  
  for (const innerId of normalizedIds) {
    // 直接使用规范化的ID，不再需要转换
    const keyIdArg = tx.pure.vector('u8', fromHex(innerId));
    const objectArg = tx.object(innerId);
    tx.moveCall({
      target: `${packageId}::${moduleName}::seal_approve`,
      arguments: [keyIdArg, objectArg],
    });
  }
  return await tx.build({ client: suiClient, onlyTransactionKind: true });
}

/**
 * 初始化游戏状态
 * @param playerAddresses 玩家地址数组
 * @param seed 随机种子
 * @param keyServerIds 密钥服务器ID列表
 * @returns 初始化的游戏状态
 */
export function initializeGameState(
  playerAddresses: string[], 
  seed: string = Date.now().toString(),
  keyServerIds: string[] = []
): GameState {
  // 创建玩家
  const players: Player[] = playerAddresses.map(address => ({
    address,
    hand: [],
    score: 0
  }));

  // 初始化游戏状态
  return {
    players,
    currentPlayerIndex: 0,
    deck: [], // 初始牌组为空，需要后续加密
    logs: [],
    seed,
    gameOver: false,
    keyServerIds
  };
}

/**
 * 添加游戏日志
 * @param state 游戏状态
 * @param message 日志消息
 * @param action 操作类型
 * @param playerAddress 玩家地址
 * @param cardId 卡牌ID
 * @returns 更新后的游戏状态
 */
export function addGameLog(
  state: GameState,
  message: string,
  action: string,
  playerAddress?: string,
  cardId?: string
): GameState {
  const newLog: GameLog = {
    id: state.logs.length,
    message,
    timestamp: new Date(),
    action,
    playerAddress,
    cardId
  };

  return {
    ...state,
    logs: [...state.logs, newLog]
  };
}

/**
 * 检查密钥服务器健康状态
 * 通过尝试简单的加密操作测试密钥服务器是否正常工作
 * 
 * @param sealClient Seal客户端
 * @returns 密钥服务器是否健康的布尔值
 */
export async function checkKeyServerHealth(
  sealClient: SealClient
): Promise<boolean> {
  try {
    // 创建一个小测试数据
    const testData = new TextEncoder().encode('health-check');
    
    // 尝试加密操作，这会触发与密钥服务器的通信
    await sealClient.encrypt({
      threshold: 1,
      packageId: 'health-check',
      id: 'health-check-' + Date.now(),
      data: testData
    });
    
    return true;
  } catch (error) {
    console.error('密钥服务器健康检查失败:', error);
    return false;
  }
}

/**
 * 获取健康的密钥服务器ID列表
 * 对多个密钥服务器进行健康检查，返回可用的服务器ID
 * 
 * @param suiClient Sui客户端
 * @param serverObjectIds 要检查的服务器ID列表
 * @returns 健康的服务器ID列表
 */
export async function getHealthyKeyServers(
  suiClient: SuiClient,
  serverObjectIds: string[]
): Promise<string[]> {
  const healthyServers: string[] = [];
  
  // 为每个服务器创建单独的客户端进行测试
  for (const serverId of serverObjectIds) {
    try {
      const client = new SealClient({
        suiClient,
        serverObjectIds: [serverId],
        verifyKeyServers: true
      });
      
      const isHealthy = await checkKeyServerHealth(client);
      if (isHealthy) {
        healthyServers.push(serverId);
      }
    } catch (error) {
      console.warn(`服务器 ${serverId} 健康检查异常:`, error);
      // 出现异常视为不健康，继续检查其他服务器
    }
  }
  
  return healthyServers;
} 