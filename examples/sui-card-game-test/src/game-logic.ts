/**
 * 卡牌游戏核心逻辑
 */
import { SealClient, SessionKey } from '@mysten/seal';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { SuiClient } from '@mysten/sui/client';
import { Card, CardType, EncryptedCard, GameState, Player } from './models';
import { 
  addGameLog, 
  constructTxBytes, 
  drawCard, 
  encryptDeck, 
  generateInitialDeck, 
  getHealthyKeyServers,
  normalizeServerIds,
  selectKeyServers,
  shuffleDeck 
} from './game-utils';
import { CardError, CryptoGameError, KeyServerError, NetworkError, ThresholdError } from './errors';
import { decryptCard } from './crypto-operations';

// 全局游戏配置
const GAME_CONFIG = {
  // 最大重试次数
  MAX_RETRIES: 3,
  // 离线模式使用的测试密钥服务器ID
  OFFLINE_KEY_SERVER_IDS: ['offline-server-1', 'offline-server-2', 'offline-server-3'],
  // 离线模式标志
  isOfflineMode: false
};

/**
 * 启用离线模式
 * 在网络不可用或测试环境中使用
 * 
 * @param enabled 是否启用
 */
export function setOfflineMode(enabled: boolean): void {
  GAME_CONFIG.isOfflineMode = enabled;
  console.log(`离线模式已${enabled ? '启用' : '禁用'}`);
}

/**
 * 验证门限值
 * 确保门限值在合理范围内
 * 
 * @param threshold 门限值
 * @param serverCount 服务器数量
 * @returns 验证结果和错误信息
 */
function validateThreshold(threshold: number, serverCount: number): { valid: boolean; error?: string } {
  if (threshold < 2) {
    return { valid: false, error: '门限值必须至少为2' };
  }
  
  if (threshold > serverCount) {
    return { valid: false, error: `门限值(${threshold})不能大于可用服务器数量(${serverCount})` };
  }
  
  // 最佳实践：门限值不应超过服务器总数的80%
  const recommendedMax = Math.floor(serverCount * 0.8);
  if (threshold > recommendedMax) {
    console.warn(`警告: 门限值(${threshold})较高，可能影响系统可用性。建议不超过${recommendedMax}`);
  }
  
  return { valid: true };
}

/**
 * 获取离线模式的加密卡牌
 * 用于在无法连接密钥服务器时生成模拟加密数据
 * 
 * @param card 原始卡牌
 * @returns 模拟加密的卡牌
 */
function getOfflineEncryptedCard(card: Card): EncryptedCard {
  // 模拟加密数据，实际上只是将卡牌JSON序列化并转为Uint8Array
  const cardJson = JSON.stringify(card);
  const encryptedData = new TextEncoder().encode(cardJson);
  
  return {
    id: card.id,
    encryptedData,
    threshold: 2,
    innerIds: GAME_CONFIG.OFFLINE_KEY_SERVER_IDS,
    ptbId: 'offline-mode'
  };
}

/**
 * 初始化游戏
 * 使用Seal SDK进行牌组加密的关键步骤：
 * 1. 验证门限值是否合理（不超过可用服务器数）
 * 2. 验证密钥服务器数量是否足够支持设定的门限值
 * 3. 使用encryptDeck函数加密整个牌组，每张卡牌都有唯一身份标识
 * 4. 分发初始手牌并更新游戏状态
 * 
 * @param sealClient Seal客户端
 * @param suiClient Sui客户端
 * @param state 游戏状态
 * @param packageId 包ID
 * @param threshold 阈值
 * @returns 更新后的游戏状态
 */
export async function initializeGame(
  sealClient: SealClient,
  suiClient: SuiClient,
  state: GameState,
  packageId: string,
  threshold: number = 2
): Promise<GameState> {
  try {
    // 获取并检查健康的密钥服务器
    let keyServerIds = state.keyServerIds || [];
    let isOffline = GAME_CONFIG.isOfflineMode;
    
    // 离线模式处理
    if (isOffline) {
      console.log('使用离线模式...');
      keyServerIds = GAME_CONFIG.OFFLINE_KEY_SERVER_IDS;
    }
    // 如果提供了密钥服务器ID，检查它们的健康状态
    else if (keyServerIds.length > 0) {
      console.log('检查密钥服务器健康状态...');
      
      let retryCount = 0;
      let healthyServers: string[] = [];
      
      // 添加重试逻辑
      while (retryCount < GAME_CONFIG.MAX_RETRIES) {
        try {
          healthyServers = await getHealthyKeyServers(suiClient, keyServerIds);
          console.log(`健康的服务器: ${healthyServers.length}/${keyServerIds.length}`);
          
          if (healthyServers.length >= threshold) {
            break; // 找到足够的健康服务器，退出重试循环
          }
          
          retryCount++;
          if (retryCount < GAME_CONFIG.MAX_RETRIES) {
            console.log(`可用服务器不足，${retryCount}秒后重试...`);
            await new Promise(resolve => setTimeout(resolve, retryCount * 1000));
          }
        } catch (error) {
          console.error('健康检查出错:', error);
          retryCount++;
          if (retryCount < GAME_CONFIG.MAX_RETRIES) {
            console.log(`健康检查出错，${retryCount}秒后重试...`);
            await new Promise(resolve => setTimeout(resolve, retryCount * 1000));
          }
        }
      }
      
      // 如果重试后仍然没有足够的健康服务器
      if (healthyServers.length < threshold) {
        console.warn('健康的密钥服务器不足，切换到离线模式');
        isOffline = true;
        keyServerIds = GAME_CONFIG.OFFLINE_KEY_SERVER_IDS;
      } else {
        // 只使用健康的服务器
        keyServerIds = healthyServers;
      }
    }
    
    // 验证门限值
    const thresholdValidation = validateThreshold(threshold, keyServerIds.length);
    if (!thresholdValidation.valid) {
      throw new ThresholdError(thresholdValidation.error || '门限值配置错误');
    }
    
    // 生成初始牌组
    const initialDeck = generateInitialDeck(state.seed);
    
    // 洗牌
    const shuffledDeck = shuffleDeck(initialDeck);
    
    // 规范化服务器ID
    keyServerIds = normalizeServerIds(keyServerIds);
    
    // 加密牌组
    let encryptedDeck: EncryptedCard[];
    
    if (isOffline) {
      // 离线模式：创建模拟加密卡牌
      console.log('使用离线模式生成模拟加密数据...');
      encryptedDeck = shuffledDeck.map(card => getOfflineEncryptedCard(card));
    } else {
      // 在线模式：使用Seal加密
      console.log('使用Seal加密牌组...');
      encryptedDeck = await encryptDeck(
        sealClient, 
        shuffledDeck, 
        packageId, 
        threshold,
        keyServerIds
      );
    }
    
    // 分发初始手牌
    let updatedState = { 
      ...state, 
      deck: encryptedDeck,
      keyServerIds: keyServerIds, // 显式指定类型并更新使用健康的服务器列表
      offlineMode: isOffline // 记录当前是否处于离线模式
    } as GameState; // 使用类型断言
    const initialHandSize = 5; // 每位玩家初始手牌数量
    
    for (let i = 0; i < initialHandSize; i++) {
      for (let playerIndex = 0; playerIndex < state.players.length; playerIndex++) {
        const [drawnCard, remainingDeck] = drawCard(updatedState.deck);
        
        if (drawnCard) {
          // 更新玩家手牌
          const updatedPlayers = [...updatedState.players];
          updatedPlayers[playerIndex] = {
            ...updatedPlayers[playerIndex],
            hand: [...updatedPlayers[playerIndex].hand, drawnCard as EncryptedCard]
          };
          
          // 更新游戏状态
          updatedState = {
            ...updatedState,
            players: updatedPlayers,
            deck: remainingDeck
          };
        }
      }
    }
    
    // 添加游戏日志
    updatedState = addGameLog(
      updatedState, 
      `游戏初始化完成${isOffline ? ' (离线模式)' : ''}`, 
      "init", 
      undefined
    );
    
    return updatedState;
  } catch (error) {
    // 使用改进的错误处理
    if (error instanceof CryptoGameError) {
      console.error(`[${error.name}] 游戏初始化失败: ${error.message}`);
    } else {
      console.error('游戏初始化失败:', error);
    }
    
    // 尝试回退到离线模式
    if (!GAME_CONFIG.isOfflineMode && (error instanceof NetworkError || error instanceof KeyServerError)) {
      console.warn('检测到网络问题，尝试切换到离线模式重新初始化...');
      GAME_CONFIG.isOfflineMode = true;
      return initializeGame(sealClient, suiClient, state, packageId, threshold);
    }
    
    throw error;
  }
}

/**
 * 抽卡
 * @param state 游戏状态
 * @returns 更新后的游戏状态
 */
export function drawCardAction(state: GameState): GameState {
  if (state.deck.length === 0) {
    return addGameLog(state, "牌组已空!", "draw_card_failed", state.players[state.currentPlayerIndex].address);
  }
  
  const [drawnCard, remainingDeck] = drawCard(state.deck);
  
  if (!drawnCard) {
    return addGameLog(state, "抽卡失败", "draw_card_failed", state.players[state.currentPlayerIndex].address);
  }
  
  // 更新玩家手牌
  const updatedPlayers = [...state.players];
  updatedPlayers[state.currentPlayerIndex] = {
    ...updatedPlayers[state.currentPlayerIndex],
    hand: [...updatedPlayers[state.currentPlayerIndex].hand, drawnCard as EncryptedCard]
  };
  
  // 更新游戏状态
  let updatedState = {
    ...state,
    players: updatedPlayers,
    deck: remainingDeck
  };
  
  // 添加游戏日志
  updatedState = addGameLog(
    updatedState, 
    `玩家${state.currentPlayerIndex + 1}抽了一张牌`, 
    "draw_card", 
    state.players[state.currentPlayerIndex].address,
    (drawnCard as EncryptedCard).id
  );
  
  return updatedState;
}

/**
 * 出牌
 * @param state 游戏状态
 * @param cardIndex 手牌索引
 * @param cardData 解密后的卡牌数据
 * @returns 更新后的游戏状态
 */
export function playCardAction(
  state: GameState, 
  cardIndex: number, 
  cardData: Card
): GameState {
  const currentPlayer = state.players[state.currentPlayerIndex];
  
  if (cardIndex >= currentPlayer.hand.length) {
    return addGameLog(
      state, 
      "无效的卡牌索引", 
      "play_card_failed", 
      currentPlayer.address
    );
  }
  
  const playedCard = currentPlayer.hand[cardIndex];
  
  // 从玩家手牌中移除该卡牌
  const updatedHand = [
    ...currentPlayer.hand.slice(0, cardIndex),
    ...currentPlayer.hand.slice(cardIndex + 1)
  ];
  
  // 更新玩家
  const updatedPlayers = [...state.players];
  updatedPlayers[state.currentPlayerIndex] = {
    ...updatedPlayers[state.currentPlayerIndex],
    hand: updatedHand
  };
  
  // 基本状态更新
  let updatedState = {
    ...state,
    players: updatedPlayers
  };
  
  // 根据卡牌类型执行不同逻辑
  switch (cardData.type) {
    case CardType.NORMAL:
      // 普通牌，加分
      updatedPlayers[state.currentPlayerIndex].score += cardData.value;
      updatedState = {
        ...updatedState,
        players: updatedPlayers
      };
      
      updatedState = addGameLog(
        updatedState,
        `玩家${state.currentPlayerIndex + 1}出了一张普通牌，值为${cardData.value}`,
        "play_normal_card",
        currentPlayer.address,
        playedCard.id
      );
      break;
      
    case CardType.BOMB:
      // 炸弹牌，游戏结束，当前玩家失败
      if (hasDefuseCard(currentPlayer)) {
        // 如果有拆弹牌，则使用拆弹牌解除炸弹
        updatedState = useDefuseCard(updatedState);
        updatedState = addGameLog(
          updatedState,
          `玩家${state.currentPlayerIndex + 1}抽到了炸弹，但使用拆弹牌解除了危险`,
          "defuse_bomb",
          currentPlayer.address,
          playedCard.id
        );
      } else {
        // 没有拆弹牌，游戏结束
        updatedState = {
          ...updatedState,
          gameOver: true,
          winner: getOtherPlayerAddress(state)
        };
        
        updatedState = addGameLog(
          updatedState,
          `玩家${state.currentPlayerIndex + 1}抽到了炸弹爆炸！游戏结束`,
          "bomb_exploded",
          currentPlayer.address,
          playedCard.id
        );
      }
      break;
      
    case CardType.SHUFFLE:
      // 洗牌，重新洗牌
      updatedState = {
        ...updatedState,
        deck: shuffleDeck(updatedState.deck)
      };
      
      updatedState = addGameLog(
        updatedState,
        `玩家${state.currentPlayerIndex + 1}使用了洗牌卡，牌组已重新洗牌`,
        "shuffle_deck",
        currentPlayer.address,
        playedCard.id
      );
      break;
      
    case CardType.FUTURE_SIGHT:
      // 预知未来牌，功能已在解密步骤实现，这里仅记录日志
      updatedState = addGameLog(
        updatedState,
        `玩家${state.currentPlayerIndex + 1}使用了预知未来卡，查看了牌组顶部的卡牌`,
        "future_sight",
        currentPlayer.address,
        playedCard.id
      );
      break;
      
    case CardType.DEFUSE:
      // 拆弹牌，保留在手牌中备用
      updatedState = addGameLog(
        updatedState,
        `玩家${state.currentPlayerIndex + 1}获得了拆弹卡`,
        "get_defuse",
        currentPlayer.address,
        playedCard.id
      );
      break;
  }
  
  // 切换到下一个玩家
  updatedState = switchPlayer(updatedState);
  
  return updatedState;
}

/**
 * 切换玩家
 * @param state 游戏状态
 * @returns 更新后的游戏状态
 */
export function switchPlayer(state: GameState): GameState {
  const nextPlayerIndex = (state.currentPlayerIndex + 1) % state.players.length;
  
  return {
    ...state,
    currentPlayerIndex: nextPlayerIndex
  };
}

/**
 * 检查玩家是否有拆弹牌
 * @param player 玩家
 * @returns 是否有拆弹牌
 */
function hasDefuseCard(player: Player): boolean {
  // 注意：在实际游戏中，需要先解密卡牌才能知道类型
  // 这里假设我们已经知道了卡牌类型
  return player.hand.some(card => card.id.includes('defuse'));
}

/**
 * 使用拆弹牌
 * @param state 游戏状态
 * @returns 更新后的游戏状态
 */
function useDefuseCard(state: GameState): GameState {
  const currentPlayer = state.players[state.currentPlayerIndex];
  
  // 找到第一张拆弹牌
  const defuseCardIndex = currentPlayer.hand.findIndex(card => 
    card.id.includes('defuse')
  );
  
  if (defuseCardIndex === -1) {
    return state; // 没有找到拆弹牌，不应该发生
  }
  
  // 从玩家手牌中移除拆弹牌
  const updatedHand = [
    ...currentPlayer.hand.slice(0, defuseCardIndex),
    ...currentPlayer.hand.slice(defuseCardIndex + 1)
  ];
  
  // 更新玩家
  const updatedPlayers = [...state.players];
  updatedPlayers[state.currentPlayerIndex] = {
    ...updatedPlayers[state.currentPlayerIndex],
    hand: updatedHand
  };
  
  return {
    ...state,
    players: updatedPlayers
  };
}

/**
 * 获取另一个玩家的地址
 * @param state 游戏状态
 * @returns 另一个玩家的地址
 */
function getOtherPlayerAddress(state: GameState): string {
  const otherPlayerIndex = (state.currentPlayerIndex + 1) % state.players.length;
  return state.players[otherPlayerIndex].address;
}

/**
 * 解密并出牌
 * 使用Seal解密卡牌数据，并执行相应的游戏动作
 * 
 * @param sealClient Seal客户端
 * @param suiClient Sui客户端
 * @param state 游戏状态
 * @param sessionKey 会话密钥
 * @param packageId 包ID
 * @param cardIndex 手牌索引
 * @param moduleName 模块名
 * @returns 更新后的游戏状态和解密的卡牌
 */
export async function decryptAndPlayCard(
  sealClient: SealClient,
  suiClient: SuiClient,
  state: GameState,
  sessionKey: SessionKey,
  packageId: string,
  cardIndex: number,
  moduleName: string = 'seal'
): Promise<{ state: GameState; card: Card }> {
  const currentPlayer = state.players[state.currentPlayerIndex];
  
  if (cardIndex >= currentPlayer.hand.length) {
    throw new CardError(`无效的卡牌索引: ${cardIndex}`);
  }
  
  const encryptedCard = currentPlayer.hand[cardIndex];
  
  try {
    // 传递离线模式参数给解密函数
    const isOfflineMode = state.offlineMode === true; // 确保是布尔值
    
    // 解密卡牌
    const card = await decryptCard(
      sealClient,
      suiClient,
      encryptedCard,
      sessionKey,
      packageId,
      moduleName,
      isOfflineMode
    );
    
    // 执行出牌动作
    const updatedState = playCardAction(state, cardIndex, card);
    
    return { state: updatedState, card };
  } catch (error) {
    console.error('解密并出牌失败:', error);
    
    if (error instanceof CryptoGameError) {
      throw error;
    } else {
      throw new CardError(`解密并出牌失败: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}