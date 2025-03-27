/**
 * 加密卡牌游戏测试项目入口文件
 */

// 导出实体模型
export * from './models';

// 导出游戏工具函数
export * from './game-utils';

// 导出游戏逻辑
export * from './game-logic';

// 导出加密操作
export * from './crypto-operations';

// 游戏版本
export const VERSION = '1.0.0';

// 导出游戏相关常量
export const CONSTANTS = {
  INITIAL_HAND_SIZE: 5,
  DEFAULT_THRESHOLD: 2,
  FUTURE_SIGHT_COUNT: 3,
  SESSION_KEY_TTL_MIN: 10
}; 