/**
 * 加密操作测试
 */
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { SuiClient } from '@mysten/sui/client';
import { SealClient, SessionKey } from '@mysten/seal';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { 
  createKeypairFromBase64, 
  createSessionKey, 
  decryptCard, 
  viewTopCards 
} from '../crypto-operations';
import { initializeSealClient } from '../game-utils';
import { Card, CardType, EncryptedCard } from '../models';

// 模拟Seal客户端
vi.mock('@mysten/seal', () => {
  return {
    SealClient: vi.fn().mockImplementation(() => {
      return {
        encrypt: vi.fn().mockImplementation(async ({ data }) => {
          // 简单地将数据作为加密结果返回
          return {
            encryptedObject: data,
            key: new Uint8Array(32).fill(1)
          };
        }),
        decrypt: vi.fn().mockImplementation(async ({ data }) => {
          // 为测试目的，根据不同的加密数据返回不同的解密结果
          const buffer = Buffer.from(data);
          if (buffer[0] === 1) {
            return Buffer.from(JSON.stringify({
              id: 'card-1',
              type: 'normal',
              value: 5
            }));
          }
          if (buffer[0] === 4) {
            return Buffer.from(JSON.stringify({
              id: 'card-2',
              type: 'normal',
              value: 8
            }));
          }
          if (buffer[0] === 7) {
            return Buffer.from(JSON.stringify({
              id: 'card-3',
              type: 'normal',
              value: 3
            }));
          }
          if (buffer[0] === 10) {
            return Buffer.from(JSON.stringify({
              id: 'card-bomb',
              type: 'bomb',
              value: 0
            }));
          }
          if (buffer[0] === 13) {
            return Buffer.from(JSON.stringify({
              id: 'card-shuffle',
              type: 'shuffle',
              value: 0
            }));
          }
          if (buffer[0] === 16) {
            return Buffer.from(JSON.stringify({
              id: 'card-future',
              type: 'future_sight',
              value: 0
            }));
          }
          
          // 默认返回
          return Buffer.from(JSON.stringify({
            id: 'unknown-card',
            type: 'normal',
            value: 1
          }));
        })
      };
    }),
    SessionKey: vi.fn().mockImplementation(({ address, packageId, ttlMin }) => {
      return {
        address,
        packageId,
        ttlMin,
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

// 测试私钥（示例用，实际使用时应当替换为真实的私钥）
const TEST_PRIVATE_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='; // 仅用于测试的伪私钥

describe('加密操作', () => {
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
  
  it('应该能够从Base64私钥创建密钥对', () => {
    const testKeypair = createKeypairFromBase64(TEST_PRIVATE_KEY);
    expect(testKeypair).toBeDefined();
    expect(testKeypair.getPublicKey()).toBeDefined();
  });
  
  it('应该能够创建会话密钥', async () => {
    const address = '0x123456789abcdef';
    const packageId = '0x12345';
    const ttlMin = 10;
    
    const sessionKey = await createSessionKey(address, packageId, keypair, ttlMin);
    
    expect(sessionKey).toBeDefined();
    expect(sessionKey).toHaveProperty('sign');
  });
  
  it('应该能够解密卡牌', async () => {
    const encryptedCard: EncryptedCard = {
      id: 'card-1',
      encryptedData: new Uint8Array([1, 2, 3])
    };
    
    const address = '0x123456789abcdef';
    const packageId = '0x12345';
    const sessionKey = await createSessionKey(address, packageId, keypair);
    
    const decryptedCard = await decryptCard(
      sealClient,
      suiClient,
      encryptedCard,
      sessionKey,
      packageId
    );
    
    expect(decryptedCard).toBeDefined();
    expect(decryptedCard.id).toBe('card-1');
    expect(decryptedCard.type).toBe('normal');
    expect(decryptedCard.value).toBe(5);
  });
  
  it('应该能够查看牌组顶部的卡牌', async () => {
    const deck: EncryptedCard[] = [
      { id: 'card-1', encryptedData: new Uint8Array([1, 2, 3]) },
      { id: 'card-2', encryptedData: new Uint8Array([4, 5, 6]) },
      { id: 'card-3', encryptedData: new Uint8Array([7, 8, 9]) },
      { id: 'card-bomb', encryptedData: new Uint8Array([10, 11, 12]) }
    ];
    
    const address = '0x123456789abcdef';
    const packageId = '0x12345';
    const sessionKey = await createSessionKey(address, packageId, keypair);
    
    const topCards = await viewTopCards(
      sealClient,
      suiClient,
      deck,
      sessionKey,
      packageId,
      'seal',
      3
    );
    
    expect(topCards).toBeDefined();
    expect(topCards.length).toBe(3);
    expect(topCards[0].id).toBe('card-1');
    expect(topCards[1].id).toBe('card-2');
    expect(topCards[2].id).toBe('card-3');
  });
}); 