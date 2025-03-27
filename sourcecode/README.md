# @mysten/seal

## 简介

Seal是一个基于身份的加密(IBE)系统，提供了安全的数据加密和访问控制功能。它使用分布式密钥服务器和门限密码学来确保数据的安全性和可用性。

**警告**: 这是Seal的开发者预览版本。它属于实验性质，不保证正常运行时间或正确性。使用风险自负。

## 详细文档

- [架构设计](./doc/ARCHITECTURE_CN.md)
- [使用指南](./doc/USAGE_CN.md)

## 功能特点

- 基于身份的加密 (IBE)
- 分布式密钥管理
- 门限解密
- 细粒度访问控制
- 与Sui区块链集成

## 快速开始

```typescript
import { SealClient, SessionKey } from '@mysten/seal';

// 初始化客户端
const client = new SealClient({
  suiClient,
  serverObjectIds: ['server-1', 'server-2', 'server-3']
});

// 加密数据
const encrypted = await client.encrypt({
  threshold: 2,
  packageId: '0x...',
  id: 'document-1',
  data: new TextEncoder().encode('Hello, Seal!')
});
```

更多示例和详细用法请参考[使用指南](./doc/USAGE_CN.md)。
