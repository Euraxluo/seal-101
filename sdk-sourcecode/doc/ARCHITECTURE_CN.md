# Seal SDK 架构文档

## 功能泳道图

```mermaid
sequenceDiagram
    participant Client as 客户端
    participant SealClient as Seal客户端
    participant KeyServer as 密钥服务器
    participant SuiChain as Sui链

    %% 初始化流程
    Client->>SealClient: 创建客户端实例<br/>（指定KeyServer列表）
    SealClient->>SuiChain: 获取KeyServer信息
    SealClient->>KeyServer: 验证KeyServer有效性

    %% 加密流程
    Client->>SealClient: 请求加密数据<br/>(数据,身份标识,阈值)
    SealClient->>SealClient: 生成随机会话密钥
    SealClient->>SealClient: 使用身份加密数据
    SealClient->>Client: 返回加密结果

    %% 解密流程
    Client->>SealClient: 请求解密数据<br/>(加密数据,会话密钥)
    SealClient->>KeyServer: 请求解密密钥分片
    KeyServer->>SuiChain: 验证访问权限
    KeyServer-->>SealClient: 返回密钥分片
    SealClient->>SealClient: 重构解密密钥
    SealClient->>Client: 返回解密结果
```

## 核心组件

1. **SealClient**
   - 主要客户端接口
   - 管理密钥服务器连接
   - 处理加密/解密请求
   
2. **KeyServer**
   - 密钥存储和管理
   - 权限验证
   - 密钥分发

3. **SessionKey**
   - 会话管理
   - 临时密钥生成
   - 签名验证

4. **加密组件**
   - IBE (Identity-Based Encryption)
   - AES-GCM / HMAC-CTR
   - Shamir密钥分享

## 数据流

1. **加密流程**
   ```
   原始数据 -> DEM加密 -> IBE加密 -> 密钥分片 -> 加密对象
   ```

2. **解密流程**
   ```
   加密对象 -> 收集密钥分片 -> 重构密钥 -> IBE解密 -> DEM解密 -> 原始数据
   ```

## 安全特性

1. 基于身份的加密(IBE)
2. 门限密钥分享(t-n)
3. 零知识证明
4. 访问控制
5. 防重放攻击
```
