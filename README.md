# SEAL 密钥服务系统交互流程技术备忘录

## 1. 整体系统架构

```mermaid
graph TB
    Client[客户端应用]
    User[用户钱包]
    SealSDK[SEAL SDK]
    KS[密钥服务器]
    Smart[链上智能合约]
    
    Client -->|1. 请求解密数据| SealSDK
    SealSDK -->|2. 请求授权| User
    User -->|3. 签名授权| SealSDK
    SealSDK -->|4. 请求密钥| KS
    KS -->|5. 验证权限| Smart
    Smart -->|6. 返回验证结果| KS
    KS -->|7. 返回加密密钥| SealSDK
    SealSDK -->|8. 解密数据| Client
    
    classDef client fill:#d4f1f9,stroke:#05a,stroke-width:2px;
    classDef wallet fill:#ffe6cc,stroke:#d79b00,stroke-width:2px;
    classDef sdk fill:#dae8fc,stroke:#6c8ebf,stroke-width:2px;
    classDef server fill:#f8cecc,stroke:#b85450,stroke-width:2px;
    classDef contract fill:#d5e8d4,stroke:#82b366,stroke-width:2px;
    
    class Client client;
    class User wallet;
    class SealSDK sdk;
    class KS server;
    class Smart contract;
```

## 2. 详细交互流程

```mermaid
sequenceDiagram
    participant Client as 客户端应用
    participant SessionKey as SessionKey模块
    participant Wallet as 用户钱包
    participant ElGamal as ElGamal加密模块
    participant SealClient as SealClient
    participant KeyServer as 密钥服务器
    participant Chain as 区块链
    
    %% 1. 会话创建阶段
    rect rgb(230, 240, 255)
    note over Client, Wallet: 1. 会话创建阶段
    Client->>SessionKey: 创建SessionKey(address, packageId, ttlMin)
    SessionKey->>SessionKey: 生成Ed25519会话密钥对
    SessionKey->>SessionKey: 构建个人消息(包ID, TTL, 时间, 会话公钥)
    SessionKey->>Wallet: 请求签名个人消息
    Wallet->>Wallet: 用户确认请求
    Wallet-->>SessionKey: 返回签名
    SessionKey->>SessionKey: 验证并存储签名
    end
    
    %% 2. 密钥请求准备阶段
    rect rgb(255, 240, 230)
    note over SessionKey, ElGamal: 2. 密钥请求准备阶段
    Client->>SealClient: fetchKeys(ids, txBytes, sessionKey, threshold)
    SealClient->>SealClient: 检查缓存中是否已有密钥
    SealClient->>SessionKey: 请求getCertificate()
    SessionKey-->>SealClient: 返回证书(用户地址, 会话公钥, 时间, TTL, 签名)
    SealClient->>SessionKey: 请求createRequestParams(txBytes)
    SessionKey->>ElGamal: 生成ElGamal密钥对(egSk)
    ElGamal-->>SessionKey: 返回密钥对
    SessionKey->>SessionKey: 构建请求消息(PTB, encKey, encVerificationKey)
    SessionKey->>SessionKey: 使用会话私钥签名请求消息
    SessionKey-->>SealClient: 返回{decryptionKey, requestSignature}
    end
    
    %% 3. 服务器交互阶段
    rect rgb(230, 255, 230)
    note over SealClient, KeyServer: 3. 服务器交互阶段
    SealClient->>SealClient: 准备请求体(PTB, ElGamal公钥, 验证密钥, 签名, 证书)
    
    loop 所有密钥服务器(直到达到阈值)
        SealClient->>KeyServer: 发送fetchKey请求
        KeyServer->>KeyServer: 检查证书有效性(TTL, 时间)
        KeyServer->>KeyServer: 验证用户签名(个人消息)
        KeyServer->>KeyServer: 验证会话签名(请求数据)
        KeyServer->>Chain: 发送交易进行dry-run验证
        Chain-->>KeyServer: 返回执行结果
        
        alt 验证成功
            KeyServer->>KeyServer: 提取用户特定密钥(IBE)
            KeyServer->>KeyServer: 使用ElGamal公钥加密密钥
            KeyServer-->>SealClient: 返回加密密钥列表
        else 验证失败
            KeyServer-->>SealClient: 返回错误(无访问权限/签名无效等)
        end
    end
    end
    
    %% 4. 解密阶段
    rect rgb(240, 230, 255)
    note over SealClient, Client: 4. 解密阶段
    SealClient->>ElGamal: 使用ElGamal私钥解密返回的密钥
    ElGamal-->>SealClient: 返回解密后的密钥
    SealClient->>SealClient: 验证密钥有效性
    SealClient->>SealClient: 存储密钥到缓存
    
    Client->>SealClient: decrypt(encryptedData, sessionKey, txBytes)
    SealClient->>SealClient: 使用解密后的密钥对数据进行解密
    SealClient-->>Client: 返回解密后的数据
    Client->>Client: 处理并展示解密后的数据
    end
```

## 3. 重要组件详解

```mermaid
classDiagram
    class SessionKey {
        -address: string
        -packageId: string
        -creationTimeMs: number
        -ttlMin: number
        -sessionKey: Ed25519Keypair
        -personalMessageSignature: string
        +isExpired(): boolean
        +getAddress(): string
        +getPackageId(): string
        +getPersonalMessage(): Uint8Array
        +setPersonalMessageSignature(signature): void
        +getCertificate(): Certificate
        +createRequestParams(txBytes): RequestParams
    }
    
    class Certificate {
        +user: string
        +session_vk: string
        +creation_time: number
        +ttl_min: number
        +signature: string
    }
    
    class SealClient {
        -cachedKeys: Map
        -keyServers: KeyServer[]
        -timeout: number
        +encrypt(options): EncryptedObject
        +decrypt(options): Uint8Array
        +fetchKeys(options): void
        -getKeyServers(): KeyServer[]
    }
    
    class KeyServer {
        +objectId: string
        +url: string
        +keyType: KeyServerType
        +pk: Uint8Array
    }
    
    class ElGamalEncryption {
        +generateSecretKey(): Uint8Array
        +toPublicKey(sk): Uint8Array
        +toVerificationKey(sk): Uint8Array
        +encrypt(rng, msg, pk): [Uint8Array, Uint8Array]
        +decrypt(sk, ciphertext): Uint8Array
    }
    
    class IBEEncryption {
        +extract(masterKey, id): UserSecretKey
        +verifyUserSecretKey(key, id, pk): boolean
    }
    
    SessionKey -- Certificate : 创建 >
    SessionKey -- SealClient : 使用 >
    SealClient -- KeyServer : 请求 >
    SealClient -- ElGamalEncryption : 使用 >
    KeyServer -- IBEEncryption : 使用 >
```

## 4. 关键流程详解

### 4.1 会话创建与授权流程

```mermaid
flowchart TD
    A[开始] --> B[创建SessionKey]
    B --> C[生成Ed25519会话密钥对]
    C --> D[构建个人消息]
    D --> E{请求用户签名}
    
    E -->|用户拒绝| F[失败]
    E -->|用户同意| G[获取签名]
    G --> H[验证签名]
    H -->|签名无效| F
    H -->|签名有效| I[存储签名]
    I --> J[会话创建成功]
    
    subgraph 个人消息内容
    M1[包ID]
    M2[TTL时间]
    M3[创建时间戳]
    M4[会话公钥]
    end
    
    D -.-> M1
    D -.-> M2
    D -.-> M3
    D -.-> M4
```

### 4.2 密钥请求与ElGamal加密流程

```mermaid
flowchart TD
    A[开始] --> B[生成ElGamal临时密钥对]
    B --> C[派生ElGamal公钥]
    B --> D[派生ElGamal验证密钥]
    C --> E[构建请求数据]
    D --> E
    E --> F[用会话密钥签名请求]
    F --> G[发送请求到密钥服务器]
    
    G --> H{密钥服务器处理}
    H -->|验证成功| I[服务器提取密钥]
    H -->|验证失败| J[返回错误]
    
    I --> K[服务器用ElGamal公钥加密密钥]
    K --> L[返回加密密钥]
    
    L --> M[客户端用ElGamal私钥解密]
    M --> N[验证解密密钥有效性]
    N -->|无效| O[抛出错误]
    N -->|有效| P[密钥获取成功]
    
    subgraph ElGamal加密过程
    EG1[c1 = g^r]
    EG2[c2 = m * h^r]
    end
    
    K -.-> EG1
    K -.-> EG2
```

### 4.3 密钥服务器验证流程

```mermaid
flowchart LR
    A[收到请求] --> B{检查证书有效性}
    B -->|无效| C[返回证书无效错误]
    B -->|有效| D{验证用户签名}
    
    D -->|无效| E[返回签名无效错误]
    D -->|有效| F{验证会话签名}
    
    F -->|无效| G[返回会话签名无效错误]
    F -->|有效| H[解析PTB]
    
    H --> I[执行dry-run交易]
    I --> J{检查执行结果}
    
    J -->|执行失败| K[返回无访问权限错误]
    J -->|执行成功| L[提取用户密钥]
    
    L --> M[ElGamal加密密钥]
    M --> N[返回加密密钥]
```

### 4.4 PTB验证与访问控制流程

```mermaid
flowchart TD
    A[构建PTB] --> B[包含seal_approve调用]
    B --> C[指定访问对象ID]
    C --> D[发送到服务器]
    
    D --> E[服务器dry-run执行PTB]
    E --> F{执行结果}
    
    F -->|成功| G[用户有访问权限]
    F -->|失败| H[用户无访问权限]
    
    subgraph PTB内容
    P1[Target: packageId::moduleName::seal_approve]
    P2[Arguments: id, allowlistId]
    end
    
    B -.-> P1
    C -.-> P2
```

### 4.5 阈值密钥获取与容错机制

```mermaid
flowchart TD
    A[开始密钥获取] --> B[确定阈值要求]
    B --> C[检查缓存是否已有足够密钥]
    
    C -->|已有足够密钥| D[返回成功]
    C -->|缓存不足| E[准备从服务器获取]
    
    E --> F[并行请求多个密钥服务器]
    
    F --> G1[服务器1]
    F --> G2[服务器2]
    F --> G3[服务器3]
    F --> GN[...更多服务器]
    
    G1 --> H[收集返回结果]
    G2 --> H
    G3 --> H
    GN --> H
    
    H --> I{达到阈值数量?}
    I -->|是| J[终止剩余请求]
    I -->|否| K{错误是否过多?}
    
    J --> L[成功返回]
    K -->|是| M[返回错误]
    K -->|否| N[继续等待其他服务器]
    N --> I
```

## 5. 关键概念解释

```mermaid
mindmap
  root((SEAL密钥管理系统))
    会话机制
      SessionKey
        临时Ed25519密钥对
        有时间限制(TTL)
        用户授权签名
        会话签名生成
      Certificate
        用户地址
        会话公钥
        创建时间
        有效期限
        用户签名
    加密机制
      IBE(基于身份的加密)
        使用任意字符串作为公钥
        密钥派生函数
        完整ID构造
      ElGamal加密
        临时密钥生成
        公钥和验证密钥
        加密过程
        解密过程
    访问控制
      PTB(可编程交易块)
        seal_approve函数
        链上验证逻辑
        干运行执行
      权限验证
        智能合约权限检查
        链上状态验证
    安全机制
      双重签名保护
        用户授权签名
        会话操作签名
      密钥传输保护
        ElGamal加密保护
        服务器验证机制
      阈值密钥共享
        多服务器支持
        容错机制
        验证与缓存
```

## 6. 常见问题解答

```mermaid
graph TD
    Q1[PTB是什么?] --> A1[PTB是Sui区块链的可编程交易块<br/>在SEAL中用于验证用户访问权限<br/>包含seal_approve等函数调用]
    
    Q2[为什么使用ElGamal加密?] --> A2[ElGamal是公钥加密系统<br/>可以安全传输密钥<br/>支持同态加密特性<br/>与IBE加密兼容]
    
    Q3[会话密钥如何保障安全?] --> A3[有严格的时间限制(1-10分钟)<br/>需要用户钱包签名授权<br/>会话密钥只在客户端内存中<br/>每个会话独立生成新密钥]
    
    Q4[阈值机制有什么作用?] --> A4[允许从多个服务器获取密钥<br/>只需达到阈值数量即可解密<br/>提高系统可用性和容错性<br/>防止单点故障或恶意服务器]
    
    Q5[用户如何控制谁能解密?] --> A5[通过智能合约定义访问逻辑<br/>可基于任何链上状态控制<br/>如所有权、权限列表、支付状态等<br/>灵活且可编程的访问控制]
```

## 7. 技术参数表

```mermaid
classDiagram
    class 技术参数 {
        会话TTL: 1-10分钟
        ElGamal密钥长度: 32字节
        会话密钥类型: Ed25519
        IBE类型: Boneh-Franklin IBE
        曲线: BLS12-381
        请求超时: 可配置(默认10秒)
        HTTP头: Request-Id, SDK类型和版本
        PTB格式: 符合valid_ptb验证
    }
```