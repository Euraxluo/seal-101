# 加密卡牌游戏测试

这是一个基于Vitest的测试项目，用于实现和测试加密卡牌游戏的核心逻辑。该游戏使用Sui区块链和Seal加密框架提供安全的卡牌游戏体验。

## 项目简介

加密卡牌游戏是一个基于卡牌的回合制游戏，使用了Seal身份基加密(IBE)框架来确保游戏公平性和安全性。游戏中的每张卡牌都被加密存储，只有在特定条件下才能被解密和使用。

## 功能特点

- **基于IBE的卡牌加密**：所有卡牌都通过Seal框架加密，确保玩家无法提前知道牌组中的卡牌
- **安全的牌组管理**：使用门限加密方案，需要多个密钥服务器协作才能解密卡牌
- **多样化的卡牌类型**：普通牌、炸弹牌、洗牌牌、预知未来牌、拆弹牌等
- **细粒度的权限控制**：基于Sui区块链的访问控制系统

## 项目结构

```
sui-card-game-test/
├── src/
│   ├── models.ts             # 游戏实体模型定义
│   ├── game-utils.ts         # 游戏工具函数
│   ├── game-logic.ts         # 游戏核心逻辑
│   ├── crypto-operations.ts  # 加密相关操作
│   └── tests/                # 测试文件目录
│       ├── game-initialization.test.ts  # 游戏初始化测试
│       ├── game-logic.test.ts           # 游戏逻辑测试
│       └── crypto-operations.test.ts    # 加密操作测试
├── package.json              # 项目依赖
├── tsconfig.json             # TypeScript配置
└── vitest.config.ts          # Vitest配置
```

## 技术栈

- **TypeScript**: 强类型JavaScript超集
- **Vitest**: 现代测试框架
- **Sui SDK**: Sui区块链交互库
- **Seal SDK**: 基于身份的加密框架

## 游戏规则

1. 游戏开始时，系统创建一个包含多种卡牌的牌组，使用Seal加密后洗牌
2. 玩家轮流抽卡和出牌
3. 不同类型的卡牌有不同效果：
   - **普通牌**：增加玩家分数
   - **炸弹牌**：触发游戏结束，除非玩家有拆弹牌
   - **洗牌牌**：重新洗牌
   - **预知未来牌**：允许玩家查看牌组顶部的几张牌
   - **拆弹牌**：可以抵消炸弹牌的效果
4. 当玩家抽到炸弹牌且没有拆弹牌时，游戏结束，该玩家失败

## 如何运行测试

1. 安装依赖：
```
npm install
```

2. 运行测试：
```
npm test
```

3. 查看测试覆盖率：
```
npm test -- --coverage
```

## 密钥生成示例

```typescript
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { fromB64, toB64 } from "@mysten/sui/utils";

// 创建一个新的密钥对
const keypair = new Ed25519Keypair();
console.log("地址:", keypair.getPublicKey().toSuiAddress());
console.log("私钥:", toB64(keypair.export().privateKey));

// 从已有私钥创建密钥对
const privateKeyBase64 = "..."; // 你的base64编码私钥
const restoredKeypair = Ed25519Keypair.fromSecretKey(fromB64(privateKeyBase64));
```

## 注意事项

- 这是一个测试项目，主要用于验证游戏逻辑和密码学操作
- 实际部署时需要使用真实的Sui区块链环境和Seal密钥服务器
- 为了测试目的，项目中的许多操作都使用了模拟数据 