# Seal SDK 使用指南

## 应用领域

### 1. 隐私数据保护
- 医疗健康记录加密存储
- 个人身份信息保护
- 金融交易数据保护

### 2. 权限访问控制
- 企业文档管理
- 知识产权保护
- 多方协作系统

### 3. 区块链应用
- 智能合约数据加密
- 跨链数据传输
- NFT内容加密

### 4. 数据共享
- 多机构数据协作
- 研究数据共享
- 分布式存储系统

## 接口功能梳理

### 主要接口

1. **SealClient**
```typescript
class SealClient {
  // 初始化客户端
  constructor(options: SealClientOptions)
  
  // 加密数据
  async encrypt({
    threshold,    // 解密所需的最小密钥数量
    packageId,    // 包ID
    id,          // 身份标识
    data,        // 待加密数据
    aad          // 额外认证数据
  })
  
  // 解密数据
  async decrypt({
    data,        // 加密数据
    sessionKey,  // 会话密钥
    txBytes      // 交易字节
  })
}
```

2. **SessionKey**
```typescript
class SessionKey {
  // 初始化会话密钥
  constructor({
    address,     // 用户地址
    packageId,   // 包ID
    ttlMin,      // 有效期(分钟)
    signer      // 签名器
  })
  
  // 获取证书
  async getCertificate()
  
  // 创建请求参数
  async createRequestParams(txBytes)
}
```

### 使用示例

```typescript
// 初始化客户端
const client = new SealClient({
  suiClient,
  serverObjectIds: ['key-server-1', 'key-server-2', 'key-server-3']
});

// 加密数据
const encrypted = await client.encrypt({
  threshold: 2,
  packageId: '0x...',
  id: 'document-1',
  data: new TextEncoder().encode('sensitive data')
});

// 创建会话密钥
const sessionKey = new SessionKey({
  address: '0x...',
  packageId: '0x...',
  ttlMin: 10
});

// 解密数据
const decrypted = await client.decrypt({
  data: encrypted,
  sessionKey,
  txBytes: txBytes
});
```

## 最佳实践

1. **密钥服务器配置**
   - 使用多个密钥服务器提高可用性
   - 合理设置阈值平衡安全性和可用性
   - 定期验证密钥服务器状态

2. **会话管理**
   - 合理设置会话有效期
   - 及时更新过期会话
   - 妥善保管会话密钥

3. **错误处理**
   - 实现完整的错误处理流程
   - 监控解密失败情况
   - 保留必要的审计日志

4. **性能优化**
   - 批量处理加密/解密请求
   - 缓存常用密钥
   - 使用适当的加密模式
```
