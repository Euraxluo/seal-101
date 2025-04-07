# Seal 密钥管理系统 - 核心模块

> 部署地址: seal:0x2845082f5a5f65756b583e59a9d994aaaa36e7fef7eff5797ab1969921544646

## 1. 模块概述

Seal核心模块实现了密钥管理系统的基础架构，提供密钥服务器注册、密钥派生、多项式处理和有限域运算等关键功能。该模块是整个Seal系统的基础，与链下服务器紧密协作，共同构建了一个安全、可扩展的密钥管理生态系统。

## 2. 系统架构

Seal系统采用混合架构，链上合约负责身份验证、访问控制和密钥服务器管理，而链下服务器负责密钥生成和安全分发。

### 2.1 链上链下协作架构

```mermaid
flowchart TD
    subgraph 链上组件[Seal链上合约]
        KeyRegistry[密钥服务器注册表]
        Polynomial[多项式计算]
        GF256[有限域运算]
        Crypto[密码学原语]
    end
    
    subgraph 链下组件[密钥服务器]
        Server[服务器核心]
        IBE[基于身份加密]
        PtbValidator[交易验证]
        Cache[缓存系统]
        ElGamal[ElGamal加密]
    end
    
    Client[客户端应用] -- 1.加密数据 --> Crypto
    Client -- 2.请求密钥 --> Server
    
    Server -- 3.验证请求 --> KeyRegistry
    KeyRegistry -- 4.确认授权 --> Server
    
    Server -- 5.派生密钥 --> IBE
    IBE -- 6.返回密钥 --> Server
    Server -- 7.加密密钥 --> ElGamal
    ElGamal -- 8.返回加密密钥 --> Server
    Server -- 9.发送加密密钥 --> Client
    
    Client -- 10.解密数据 --> Client
```

### 2.2 核心组件交互图

```mermaid
sequenceDiagram
    actor 用户
    participant 密钥注册表 as KeyRegistry
    participant 服务器对象 as KeyServerObject
    participant 密钥服务器 as KeyServer
    participant 客户端 as Client
    
    用户->>密钥注册表: 注册新的密钥服务器(register_key_server)
    密钥注册表->>服务器对象: 创建服务器对象(id, 描述, URL, 公钥)
    服务器对象-->>密钥注册表: 返回服务器对象ID
    密钥注册表-->>用户: 返回注册确认
    
    Client->>密钥注册表: 查询服务器公钥(get_public_keys)
    密钥注册表->>服务器对象: 读取公钥数据
    服务器对象-->>密钥注册表: 返回服务器公钥列表
    密钥注册表-->>Client: 返回公钥信息
    
    Client->>Client: 使用服务器公钥加密数据
    Client->>KeyServer: 发送密钥请求(带PTB)
    KeyServer->>服务器对象: 验证权限(链上验证)
    服务器对象-->>KeyServer: 返回验证结果
    KeyServer->>Client: 返回加密的密钥
```

## 3. 核心模块详解

### 3.1 密钥服务器注册表 (`key_registry.move`)

此模块管理Seal系统中所有密钥服务器的注册、更新和查询。

**主要功能：**
- 注册新的密钥服务器
- 更新服务器信息(URL, 描述)
- 查询服务器公钥
- 验证服务器权限

**关键方法：**
```move
/// 注册新密钥服务器
public fun register_key_server(
    _: &mut TxContext,
    description: vector<u8>,
    url: vector<u8>,
    public_key: vector<u8>,
): (ID, KeyServer) { ... }

/// 获取公钥列表
public fun get_public_keys(registry: &KeyRegistry, ids: vector<ID>): vector<vector<u8>> { ... }
```

**与链下服务器的交互：**
- 链下服务器启动时会验证自己是否已在链上注册
- 客户端会从链上获取服务器公钥，用于加密数据
- 服务器处理密钥请求前会验证链上权限

### 3.2 有限域计算 (`gf256.move`)

实现GF(256)有限域上的数学运算，为多项式计算和秘密共享提供基础。

**主要功能：**
- GF(256)域上的加法、乘法、除法运算
- 多项式求值
- 域元素的序列化和表示

**与链下服务器的交互：**
- 链下服务器和链上合约使用相同的有限域运算规则
- 确保阈值密钥共享计算的一致性

### 3.3 多项式处理 (`polynomial.move`)

提供多项式操作和拉格朗日插值功能，用于阈值秘密共享实现。

**主要功能：**
- 多项式求值和插值
- Lagrange系数计算
- 阈值重建支持

**工作原理：**
```mermaid
flowchart LR
    A[创建多项式] --> B[计算份额点值]
    B --> C[分发份额]
    D[收集份额] --> E[Lagrange插值]
    E --> F[重建原始秘密]
```

### 3.4 密码学原语 (`crypto.move`)

提供哈希函数和基础密码学操作。

**主要功能：**
- 安全哈希计算
- 字节数组操作
- ID构建和验证

**与链下服务器的交互：**
- 链下服务器使用相同的哈希函数创建和验证请求
- 确保ID计算和验证的一致性

## 4. 密钥生命周期

下图展示了从密钥服务器注册到密钥使用的完整生命周期：

```mermaid
sequenceDiagram
    actor 系统管理员
    actor 数据所有者
    actor 授权用户
    participant 链上合约 as SealContract
    participant 密钥服务器 as KeyServer
    participant 密码学库 as Crypto
    
    %% 服务器注册阶段
    系统管理员->>密钥服务器: 生成IBE主密钥和公钥
    系统管理员->>链上合约: 注册密钥服务器(包含公钥)
    链上合约-->>系统管理员: 返回服务器ID
    
    %% 数据加密阶段
    数据所有者->>链上合约: 查询服务器公钥
    链上合约-->>数据所有者: 返回公钥列表
    数据所有者->>Crypto: 使用Seal加密数据
    Note over Crypto: 1. 生成随机基础密钥
    Note over Crypto: 2. 阈值分享基础密钥
    Note over Crypto: 3. 使用公钥加密份额
    Note over Crypto: 4. 用派生密钥加密实际数据
    Crypto-->>数据所有者: 返回加密对象
    
    %% 密钥请求与使用阶段
    授权用户->>链上合约: 创建证明权限的交易(PTB)
    授权用户->>密钥服务器: 请求密钥(带PTB)
    
    密钥服务器->>链上合约: 验证PTB权限
    链上合约-->>密钥服务器: 返回验证结果
    
    alt 验证通过
        密钥服务器->>密钥服务器: 提取用户密钥
        密钥服务器->>授权用户: 返回加密的密钥份额
        授权用户->>Crypto: 使用密钥份额解密数据
    else 验证失败
        密钥服务器->>授权用户: 返回访问拒绝
    end
```

## 5. 与链下服务器的数据流

```mermaid
flowchart TD
    subgraph 链上数据流
        K1[密钥服务器对象] --> K2[访问控制验证]
        K2 --> K3[权限确认]
    end
    
    subgraph 链下数据流
        S1[请求验证] --> S2[PTB解析]
        S2 --> S3[链上查询]
        S3 --> S4[权限检查]
        S4 --> S5[密钥生成]
        S5 --> S6[密钥加密]
        S6 --> S7[响应返回]
    end
    
    K1 -.-> S3
    K3 -.-> S4
```

## 6. 安全考量

Seal核心模块实现了多层安全机制：

1. **密钥隔离**：主密钥仅存在于链下服务器，链上只存储公钥
2. **阈值保护**：使用阈值密码学，要求多个服务器协作才能解密
3. **权限验证**：链上合约验证请求的合法性
4. **通信安全**：使用ElGamal加密保护服务器与客户端之间的通信
5. **密钥派生**：使用安全的密钥派生函数确保密钥安全性

## 7. 开发与部署指南

### 7.1 本地开发环境设置

```bash
# 安装Sui CLI
cargo install --locked --git https://github.com/MystenLabs/sui.git --branch main sui

# 编译包
sui move build

# 测试包
sui move test

# 发布包
sui client publish --gas-budget 10000000
```

### 7.2 与链下服务器集成

链下服务器部署需要配置以下关键参数：

1. **主密钥**：服务器的IBE主密钥
2. **链上包ID**：已部署的Seal合约地址
3. **服务器对象ID**：服务器在链上的注册ID
4. **RPC端点**：Sui网络的访问URL

链下服务器会检查并确保自己的公钥已经在链上注册，并使用主密钥提取用户密钥。

## 8. 技术规格

| 组件 | 技术实现 | 安全特性 |
|-----|---------|---------|
| 密钥派生 | 基于身份的加密 (IBE) | 密钥与用户身份绑定 |
| 阈值共享 | Shamir秘密共享 | 分布式信任，抵抗单点故障 |
| 有限域计算 | GF(256)域算法 | 高效的多项式运算 |
| 数据加密 | AES-256-GCM/HMAC-256-CTR | 强加密保障数据安全 |
| 通信安全 | ElGamal椭圆曲线加密 | 保护密钥传输安全 |

## 9. 未来发展路线

1. **更多密码学原语**：支持后量子密码学算法
2. **多链支持**：扩展到其他区块链平台
3. **密钥轮换**：实现无缝的主密钥更新机制
4. **性能优化**：优化链上合约的燃气使用
5. **联邦身份**：与外部身份提供者集成 