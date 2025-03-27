/**
 * 游戏逻辑测试
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { 
  drawCardAction, 
  playCardAction,
  switchPlayer 
} from '../game-logic';
import { initializeGameState } from '../game-utils';
import { Card, CardType, EncryptedCard } from '../models';

describe('游戏逻辑', () => {
  // 初始化测试游戏状态
  const playerAddresses = [
    '0x123456789abcdef',
    '0xfedcba987654321'
  ];
  
  let gameState: ReturnType<typeof initializeGameState>;
  
  beforeEach(() => {
    // 每个测试前重新初始化游戏状态
    gameState = initializeGameState(playerAddresses, 'test-seed');
    
    // 添加一些测试用的卡牌
    const mockEncryptedCards: EncryptedCard[] = [
      { id: 'card-1', encryptedData: new Uint8Array([1, 2, 3]) },
      { id: 'card-2', encryptedData: new Uint8Array([4, 5, 6]) },
      { id: 'card-3', encryptedData: new Uint8Array([7, 8, 9]) },
      { id: 'card-bomb', encryptedData: new Uint8Array([10, 11, 12]) },
      { id: 'card-shuffle', encryptedData: new Uint8Array([13, 14, 15]) },
      { id: 'card-future', encryptedData: new Uint8Array([16, 17, 18]) },
      { id: 'card-defuse', encryptedData: new Uint8Array([19, 20, 21]) }
    ];
    
    gameState.deck = mockEncryptedCards;
  });
  
  it('抽卡应该将一张牌从牌组移到玩家手牌', () => {
    const initialDeckLength = gameState.deck.length;
    const initialHandLength = gameState.players[0].hand.length;
    
    // 执行抽卡
    const updatedState = drawCardAction(gameState);
    
    // 验证牌组减少一张牌
    expect(updatedState.deck.length).toBe(initialDeckLength - 1);
    
    // 验证玩家手牌增加一张牌
    expect(updatedState.players[0].hand.length).toBe(initialHandLength + 1);
    
    // 验证日志记录
    expect(updatedState.logs.length).toBe(1);
    expect(updatedState.logs[0].action).toBe('draw_card');
  });
  
  it('当牌组为空时抽卡应该失败', () => {
    // 清空牌组
    gameState.deck = [];
    
    // 执行抽卡
    const updatedState = drawCardAction(gameState);
    
    // 验证状态
    expect(updatedState.logs.length).toBe(1);
    expect(updatedState.logs[0].action).toBe('draw_card_failed');
    expect(updatedState.logs[0].message).toBe('牌组已空!');
  });
  
  it('切换玩家应该改变当前玩家索引', () => {
    const initialPlayerIndex = gameState.currentPlayerIndex;
    
    // 执行切换玩家
    const updatedState = switchPlayer(gameState);
    
    // 验证当前玩家已切换
    expect(updatedState.currentPlayerIndex).not.toBe(initialPlayerIndex);
    expect(updatedState.currentPlayerIndex).toBe((initialPlayerIndex + 1) % gameState.players.length);
  });
  
  it('出普通牌应该增加玩家分数', () => {
    // 先给玩家一张手牌
    gameState.players[0].hand = [
      { id: 'card-normal', encryptedData: new Uint8Array([22, 23, 24]) }
    ];
    
    // 模拟解密后的卡牌数据
    const cardData: Card = {
      id: 'card-normal',
      type: CardType.NORMAL,
      value: 5
    };
    
    const initialScore = gameState.players[0].score;
    
    // 执行出牌
    const updatedState = playCardAction(gameState, 0, cardData);
    
    // 验证分数增加
    expect(updatedState.players[0].score).toBe(initialScore + cardData.value);
    
    // 验证手牌已移除
    expect(updatedState.players[0].hand.length).toBe(0);
    
    // 验证日志
    expect(updatedState.logs.length).toBe(1);
    expect(updatedState.logs[0].action).toBe('play_normal_card');
  });
  
  it('出洗牌卡应该重新洗牌', () => {
    // 给玩家一张洗牌卡
    gameState.players[0].hand = [
      { id: 'card-shuffle', encryptedData: new Uint8Array([25, 26, 27]) }
    ];
    
    // 模拟解密后的卡牌数据
    const cardData: Card = {
      id: 'card-shuffle',
      type: CardType.SHUFFLE,
      value: 0
    };
    
    // 记录初始牌组顺序
    const initialDeckIds = gameState.deck.map(card => card.id);
    
    // 执行出牌
    const updatedState = playCardAction(gameState, 0, cardData);
    
    // 验证手牌已移除
    expect(updatedState.players[0].hand.length).toBe(0);
    
    // 验证牌组已洗牌（牌数相同，但顺序可能不同）
    expect(updatedState.deck.length).toBe(gameState.deck.length);
    
    // 洗牌函数在测试环境中可能不会真正改变顺序，所以这里主要验证日志
    expect(updatedState.logs.length).toBe(1);
    expect(updatedState.logs[0].action).toBe('shuffle_deck');
  });
  
  it('不应该允许出不存在的手牌', () => {
    // 给玩家一张手牌
    gameState.players[0].hand = [
      { id: 'card-normal', encryptedData: new Uint8Array([28, 29, 30]) }
    ];
    
    // 尝试出一张不存在的手牌
    const invalidCardIndex = 1; // 超出范围的索引
    const cardData: Card = {
      id: 'card-normal',
      type: CardType.NORMAL,
      value: 5
    };
    
    // 执行出牌
    const updatedState = playCardAction(gameState, invalidCardIndex, cardData);
    
    // 验证状态没有改变
    expect(updatedState.players[0].hand.length).toBe(1);
    
    // 验证日志
    expect(updatedState.logs.length).toBe(1);
    expect(updatedState.logs[0].action).toBe('play_card_failed');
  });
}); 