/**
 * 卡牌游戏实体模型
 */

// 卡牌类型枚举
export enum CardType {
  NORMAL = "normal",
  BOMB = "bomb",
  SHUFFLE = "shuffle",
  FUTURE_SIGHT = "future_sight",
  DEFUSE = "defuse", // 拆弹牌
}

// 卡牌接口
export interface Card {
  id: string;
  type: CardType;
  value: number; // 对于普通牌，这是牌的值
}

/**
 * 加密卡牌接口
 * 对应Seal加密后的结构，参考Seal SDK文档中的加密对象描述
 * - encryptedData: 对应SealClient.encrypt()返回的encryptedObject
 * - threshold: 对应加密时设置的阈值(threshold)，表示解密所需的最小密钥数量
 * - innerIds: 对应加密时使用的serverObjectIds，用于验证解密权限
 */
export interface EncryptedCard {
  id: string;
  encryptedData: Uint8Array;
  ptbId?: string;      // 添加PTB ID用于追踪加密数据
  threshold: number;    // 加密门限值 
  innerIds: string[];  // 内部密钥服务器ID列表
}

// 玩家接口
export interface Player {
  address: string;
  hand: EncryptedCard[];
  score: number;
}

// 游戏日志条目
export interface GameLog {
  id: number;
  message: string;
  timestamp: Date;
  action: string; // 操作类型
  playerAddress?: string; // 操作执行者
  cardId?: string; // 相关卡牌
}

// 游戏状态
export interface GameState {
  players: Player[];
  currentPlayerIndex: number;
  deck: EncryptedCard[];
  logs: GameLog[];
  seed: string; // 游戏随机种子，用于确定性测试
  gameOver: boolean;
  winner?: string;
  keyServerIds: string[]; // 存储密钥服务器ID列表，用于Seal加密解密
  offlineMode?: boolean; // 标记游戏是否处于离线模式
}