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
  shuffleDeck 
} from './game-utils';

/**
 * 初始化游戏
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
  // 生成初始牌组
  const initialDeck = generateInitialDeck(state.seed);
  
  // 洗牌
  const shuffledDeck = shuffleDeck(initialDeck);
  
  // 加密牌组
  const encryptedDeck = await encryptDeck(sealClient, shuffledDeck, packageId, threshold);
  
  // 分发初始手牌
  let updatedState = { ...state, deck: encryptedDeck };
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
    "游戏初始化完成", 
    "init", 
    undefined
  );
  
  return updatedState;
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