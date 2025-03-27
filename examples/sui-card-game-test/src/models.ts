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

// 加密卡牌接口
export interface EncryptedCard {
  id: string;
  encryptedData: Uint8Array;
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
} 