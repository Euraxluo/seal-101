/**
 * 卡牌游戏工具函数
 */
import { Card, CardType, EncryptedCard, GameState, Player, GameLog } from './models';
import { SealClient } from '@mysten/seal';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { fromHex } from '@mysten/sui/utils';

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
 * 使用Seal加密牌组
 * @param sealClient Seal客户端
 * @param deck 牌组
 * @param packageId 包ID
 * @param threshold 阈值
 * @returns 加密后的牌组
 */
export async function encryptDeck(
  sealClient: SealClient, 
  deck: Card[], 
  packageId: string,
  threshold: number = 2
): Promise<EncryptedCard[]> {
  const encryptedCards: EncryptedCard[] = [];
  
  for (const card of deck) {
    const cardData = new TextEncoder().encode(JSON.stringify(card));
    
    // 使用Seal加密，为每张牌设置唯一标识
    const encryptedResult = await sealClient.encrypt({
      threshold, // 需要至少threshold个密钥服务器才能解密
      packageId,
      id: `card-${card.id}`,
      data: cardData
    });
    
    encryptedCards.push({
      id: card.id,
      encryptedData: encryptedResult.encryptedObject
    });
  }
  
  return encryptedCards;
}

/**
 * 根据服务器对象ID列表初始化Seal客户端
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
  for (const innerId of innerIds) {
    // 确保innerId是合法的十六进制，如果不是则将其转换为十六进制
    let hexId = innerId;
    if (!innerId.startsWith('0x')) {
      // 将普通字符串转换为十六进制
      hexId = '0x' + Buffer.from(innerId).toString('hex');
    }
    
    // 使用字符串直接作为参数，而不是尝试将其转换为二进制
    const keyIdArg = tx.pure.string(innerId);
    const objectArg = tx.object(hexId);
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
 * @returns 初始化的游戏状态
 */
export function initializeGameState(playerAddresses: string[], seed: string = Date.now().toString()): GameState {
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
    gameOver: false
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