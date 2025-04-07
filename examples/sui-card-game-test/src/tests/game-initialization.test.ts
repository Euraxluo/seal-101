/**
 * 游戏初始化测试
 */
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { SuiClient } from '@mysten/sui/client';
import { SealClient } from '@mysten/seal';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { 
  generateInitialDeck, 
  shuffleDeck, 
  initializeGameState, 
  initializeSealClient,
  getHealthyKeyServers
} from '../game-utils';
import { initializeGame } from '../game-logic';
import { CardType } from '../models';
import { createKeypairFromBase64 } from '../crypto-operations';
import { KeyServerError, ThresholdError } from '../errors';

// 模拟Seal客户端
vi.mock('@mysten/seal', () => {
  return {
    SealClient: vi.fn().mockImplementation(() => {
      return {
        encrypt: vi.fn().mockImplementation(async ({ data }) => {
          // 简单地将数据转为Base64作为加密结果
          return {
            encryptedObject: data,
            key: new Uint8Array(32).fill(1)
          };
        }),
        decrypt: vi.fn().mockImplementation(async ({ data }) => {
          // 直接返回"加密"的数据
          return data;
        })
      };
    }),
    SessionKey: vi.fn().mockImplementation(() => {
      return {
        sign: vi.fn().mockImplementation(() => {
          return new Uint8Array(64).fill(1);
        })
      };
    })
  };
});

// 模拟Sui客户端
vi.mock('@mysten/sui/client', () => {
  return {
    SuiClient: vi.fn().mockImplementation(() => {
      return {
        getObject: vi.fn(),
        executeTransactionBlock: vi.fn(),
        getDynamicFields: vi.fn(),
        getDynamicFieldObject: vi.fn(),
        getTransactionBlock: vi.fn(),
        devInspectTransactionBlock: vi.fn(),
        signAndExecuteTransactionBlock: vi.fn(),
        simulateTransactionBlock: vi.fn()
      };
    })
  };
});

// 模拟Transaction
vi.mock('@mysten/sui/transactions', () => {
  return {
    Transaction: vi.fn().mockImplementation(() => {
      return {
        pure: {
          string: vi.fn().mockReturnValue('mockedStringArg'),
          vector: vi.fn().mockReturnValue('mockedVectorArg')
        },
        object: vi.fn().mockReturnValue('mockedObjectArg'),
        moveCall: vi.fn(),
        build: vi.fn().mockResolvedValue(new Uint8Array(32).fill(1))
      };
    })
  };
});

// 模拟getHealthyKeyServers函数
vi.mock('../game-utils', async () => {
  const actual = await vi.importActual('../game-utils');
  return {
    ...(actual as object),
    getHealthyKeyServers: vi.fn().mockImplementation(async (_, serverObjectIds) => {
      // 假设所有服务器都健康
      return serverObjectIds;
    })
  };
});

// 测试私钥（示例用，实际使用时应当替换为真实的私钥）
const TEST_PRIVATE_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='; // 仅用于测试的伪私钥

describe('游戏初始化', () => {
  let suiClient: SuiClient;
  let sealClient: SealClient;
  let keypair: Ed25519Keypair;
  
  beforeAll(() => {
    // 创建测试所需的客户端和密钥对
    suiClient = new SuiClient({
      url: 'https://fullnode.devnet.sui.io' // 使用开发网络
    });
    
    const serverObjectIds = ['server1', 'server2', 'server3'];
    sealClient = initializeSealClient(suiClient, serverObjectIds);
    
    keypair = createKeypairFromBase64(TEST_PRIVATE_KEY);
  });
  
  it('应该能正确生成初始牌组', () => {
    const deck = generateInitialDeck();
    console.log('deck', deck);
    // 验证牌组中牌的数量
    expect(deck.length).toBeGreaterThan(0);
    
    // 验证牌组中包含所有类型的牌
    const normalCards = deck.filter(card => card.type === CardType.NORMAL);
    const bombCards = deck.filter(card => card.type === CardType.BOMB);
    const shuffleCards = deck.filter(card => card.type === CardType.SHUFFLE);
    const futureSightCards = deck.filter(card => card.type === CardType.FUTURE_SIGHT);
    const defuseCards = deck.filter(card => card.type === CardType.DEFUSE);
    
    expect(normalCards.length).toBe(40); // 1-10各4张
    expect(bombCards.length).toBe(3);
    expect(shuffleCards.length).toBe(2);
    expect(futureSightCards.length).toBe(2);
    expect(defuseCards.length).toBe(5);
  });
  
  it('应该能正确初始化游戏状态', () => {
    const playerAddresses = [
      '0x123456789abcdef',
      '0xfedcba987654321'
    ];
    
    // 添加密钥服务器ID
    const keyServerIds = ['server1', 'server2', 'server3'];
    
    const gameState = initializeGameState(playerAddresses, 'test-seed', keyServerIds);
    
    // 验证游戏状态
    expect(gameState.players.length).toBe(2);
    expect(gameState.players[0].address).toBe(playerAddresses[0]);
    expect(gameState.players[1].address).toBe(playerAddresses[1]);
    expect(gameState.currentPlayerIndex).toBe(0);
    expect(gameState.deck.length).toBe(0); // 初始牌组为空，需要后续加密
    expect(gameState.logs.length).toBe(0);
    expect(gameState.seed).toBe('test-seed');
    expect(gameState.gameOver).toBe(false);
    expect(gameState.keyServerIds).toEqual(keyServerIds);
  });
  
  it('应该能正确洗牌', () => {
    const seed = 'test-seed';
    const deck = generateInitialDeck(seed);
    const originalOrder = [...deck];
    
    const shuffled = shuffleDeck(deck);
    
    // 验证洗牌后的牌组与原牌组包含相同的牌
    expect(shuffled.length).toBe(originalOrder.length);
    
    // 洗牌应该改变牌的顺序
    let hasChanged = false;
    for (let i = 0; i < shuffled.length; i++) {
      if (shuffled[i].id !== originalOrder[i].id) {
        hasChanged = true;
        break;
      }
    }
    
    expect(hasChanged).toBe(true);
  });
  
  it('应该能正确初始化游戏', async () => {
    // 创建初始游戏状态
    const playerAddresses = [
      '0x123456789abcdef',
      '0xfedcba987654321'
    ];
    
    // 添加密钥服务器ID
    const keyServerIds = ['server1', 'server2', 'server3'];
    
    const gameState = initializeGameState(playerAddresses, 'test-seed', keyServerIds);
    const packageId = '0x12345';
    
    // 初始化游戏
    const initializedGame = await initializeGame(
      sealClient,
      suiClient,
      gameState,
      packageId,
      2
    );
    
    // 验证初始化后的游戏状态
    expect(initializedGame.deck.length).toBeGreaterThan(0);
    expect(initializedGame.players[0].hand.length).toBe(5); // 每位玩家5张初始手牌
    expect(initializedGame.players[1].hand.length).toBe(5);
    expect(initializedGame.logs.length).toBe(1); // 应有一条初始化完成的日志
    expect(initializedGame.logs[0].message).toBe('游戏初始化完成');
    expect(initializedGame.keyServerIds).toEqual(keyServerIds); // 保留服务器ID
  });
  
  it('当阈值不合理时应抛出错误', async () => {
    const playerAddresses = [
      '0x123456789abcdef',
      '0xfedcba987654321'
    ];
    
    const keyServerIds = ['server1', 'server2', 'server3'];
    const gameState = initializeGameState(playerAddresses, 'test-seed', keyServerIds);
    const packageId = '0x12345';
    
    // 使用无效的阈值
    await expect(initializeGame(
      sealClient,
      suiClient,
      gameState,
      packageId,
      1 // 阈值小于2
    )).rejects.toThrow(ThresholdError);
  });
}); 