# SEAL 密钥服务系统交互流程技术备忘录


## 1. 整体系统架构

```mermaid
graph TB
    Client[客户端应用]
    User[用户钱包]
    SealSDK[SEAL SDK]
    KS[密钥服务器集群]
    Smart[链上智能合约]
    KeyRegistry[密钥注册表]
    PatternContracts[访问控制模式]
    IBECore[IBE密码系统]
    Storage[加密数据存储]
    
    Client -->|"Step1: 数据加密/请求解密"| SealSDK
    SealSDK -->|"Step2: 请求授权"| User
    User -->|"Step3: 签名授权SessionKey"| SealSDK
    SealSDK -->|"Step4: 创建ElGamal临时密钥"| SealSDK
    SealSDK -->|"Step5: 签名PTB+构造请求"| SealSDK
    SealSDK -->|"Step6: 并行请求密钥分片"| KS
    KS -->|"Step7: 验证证书和签名"| KS
    KS -->|"Step8: 验证访问权限PTB"| Smart
    Smart -->|"Step9: 返回执行结果"| KS
    KS -->|"Step10: IBE密钥派生"| KS
    KS -->|"Step11: ElGamal加密密钥"| KS
    KS -->|"Step12: 返回加密密钥分片"| SealSDK
    SealSDK -->|"Step13: 重构门限密钥"| SealSDK
    SealSDK -->|"Step14: 解密数据"| SealSDK
    SealSDK -->|"Step15: 返回解密结果"| Client
    
    Smart --- KeyRegistry
    Smart --- PatternContracts
    KS --- IBECore
    Client --- Storage
    
    classDef client fill:#d4f1f9,stroke:#05a,stroke-width:2px;
    classDef wallet fill:#ffe6cc,stroke:#d79b00,stroke-width:2px;
    classDef sdk fill:#dae8fc,stroke:#6c8ebf,stroke-width:2px;
    classDef server fill:#f8cecc,stroke:#b85450,stroke-width:2px;
    classDef contract fill:#d5e8d4,stroke:#82b366,stroke-width:2px;
    classDef storage fill:#e1d5e7,stroke:#9673a6,stroke-width:2px;
    classDef crypto fill:#fff2cc,stroke:#d6b656,stroke-width:2px;
    
    class Client,Storage client;
    class User wallet;
    class SealSDK sdk;
    class KS,IBECore server;
    class Smart,KeyRegistry,PatternContracts contract;
    class IBECore crypto;
    class Storage storage;
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
    note over Client, Wallet: 阶段1: 会话创建
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
    note over SessionKey, ElGamal: 阶段2: 密钥请求准备
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
    note over SealClient, KeyServer: 阶段3: 服务器交互
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
    note over SealClient, Client: 阶段4: 解密
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

# SEAL密钥服务系统常见问题(FAQ)

## 一、SessionKey相关问题

### Q1: 什么是SessionKey，它解决了什么问题？
SessionKey是SEAL库中的关键组件，提供临时会话凭证机制，使用户能在限定时间内授权应用程序访问加密数据。它解决了以下核心问题：
- **减少频繁签名**：避免每次解密操作都需要用户确认
- **提高用户体验**：一次授权，多次使用
- **增强安全性**：授权有严格时间限制(1-10分钟)，减少长期授权风险
- **优化资源消耗**：减少链上交互频率，降低系统负载

### Q2: SessionKey的主要组成部分有哪些？
SessionKey包含以下关键属性：
- **用户地址**：与会话关联的Sui地址
- **包ID**：要访问的智能合约包ID
- **创建时间**：会话的创建时间戳
- **TTL(Time-To-Live)**：会话的有效期限（分钟）
- **会话密钥对**：临时生成的Ed25519密钥对
- **个人消息签名**：用户对会话请求的签名

### Q3: SessionKey如何防止滥用？
SessionKey通过多层机制防止滥用：
- **强制时间限制**：会话最长只能存活10分钟
- **用户明确授权**：必须通过钱包显式签名
- **单一包绑定**：每个SessionKey只能访问特定包的密钥
- **过期即失效**：过期后需重新获取用户授权
- **验证链**：密钥服务器验证用户签名和会话签名

## 二、技术选择问题

### Q4: 为什么使用PTB(Programmable Transaction Block)进行权限验证？
PTB作为权限验证机制具有显著优势：
- **灵活的访问控制**：可基于任何链上状态（如NFT所有权、支付状态等）
- **无需信任密钥服务器**：权限逻辑在链上定义，服务器只负责验证
- **可编程性**：支持创建任意复杂的访问规则
- **一致性**：所有密钥服务器使用相同的链上逻辑
- **支持升级**：可升级智能合约以改变访问规则，无需修改服务器

### Q5: 为什么SEAL选择ElGamal加密而非其他加密方案？
ElGamal加密系统在SEAL中的选择基于以下因素：
- **数学兼容性**：与IBE(基于身份的加密)系统共享相同的数学基础
- **一次性密钥特性**：特别适合"用后即弃"的临时会话模型
- **前向安全性**：即使某次通信被破解，不会影响其他会话
- **阈值支持**：适合实现分布式密钥片段重构
- **高效传输**：在相同安全级别下，密钥大小相对较小

### Q6: 为什么SEAL需要双重签名机制？
双重签名机制（用户签名和会话签名）提供多层安全保障：
- **权责分离**：用户签名证明身份和授权，会话签名保护请求完整性
- **防御多种攻击**：抵御中间人攻击、重放攻击和会话劫持
- **最小权限原则**：用户只授权有限的会话权限，而非无限制访问
- **请求绑定**：会话签名将请求内容绑定到会话，防止参数被替换

### Q7: 为什么SEAL实现阈值密钥共享？
阈值机制(t-of-n)提供以下关键优势：
- **安全冗余**：即使部分(n-t)服务器被攻破，系统仍然安全
- **高可用性**：只需任意t个服务器可用，系统即可正常工作
- **去中心化**：避免单一控制点，实现权力分散
- **抗审查**：防止单一实体拒绝提供服务
- **性能优化**：可并行请求多个服务器，选择最快响应

## 三、架构与实现问题

### Q8: SEAL与传统密钥管理系统有何不同？
SEAL系统与传统密钥管理的主要区别：

| 特性 | SEAL系统 | 传统密钥管理 |
|------|----------|------------|
| 访问控制 | 基于链上智能合约 | 基于中心化规则 |
| 用户授权 | 临时会话+钱包签名 | 长期API密钥/令牌 |
| 密钥保护 | 分布式密钥服务器 | 中心化密钥存储 |
| 验证机制 | PTB干运行+双重签名 | API权限检查 |
| 可编程性 | 高度可编程的访问控制 | 预定义的权限规则 |
| 信任模型 | 最小化信任要求 | 依赖服务提供商 |

### Q9: SEAL如何保护密钥在传输过程中的安全？
SEAL通过多层加密和保护机制确保密钥传输安全：
- **ElGamal加密**：服务器使用客户端临时公钥加密返回的密钥
- **HTTPS传输**：所有通信通过TLS加密
- **一次性密钥**：每次请求生成新的ElGamal密钥对
- **请求签名**：每个请求都有会话签名保护
- **状态隔离**：密钥服务器不保存会话状态，降低泄露风险

### Q10: IBE(基于身份的加密)在SEAL中扮演什么角色？
IBE在SEAL系统中的关键作用：
- **灵活的密钥派生**：可以从任意字符串(如对象ID)派生密钥
- **无需预先密钥交换**：密钥服务器可即时生成用户特定密钥
- **紧凑标识符**：使用简单字符串作为加密对象的标识符
- **密钥服务器结构**：支持基于主密钥派生多个用户密钥
- **高效验证**：支持高效的密钥验证算法

## 四、实际使用问题

### Q11: 如何优化SEAL系统的性能？
优化SEAL系统性能的关键策略：
- **密钥缓存**：客户端缓存已获取的密钥，避免重复请求
- **批量密钥获取**：一次请求多个密钥，减少网络往返
- **并行服务器请求**：同时向多个密钥服务器发送请求
- **早期中止**：达到阈值后终止其余请求
- **合理TTL设置**：根据使用场景设置合适的会话有效期

### Q12: SEAL系统适用于哪些应用场景？
SEAL特别适合以下应用场景：
- **加密内容平台**：提供付费或权限控制的内容访问
- **数据市场**：安全共享和交易数据资产
- **保密通信**：端到端加密消息系统
- **多方数据共享**：控制多方之间的数据访问权限
- **去中心化应用**：需要加密存储和条件访问的DApps
- **财务文件保护**：保护对财务和法律文件的访问

### Q13: 如何处理SEAL系统中的错误和异常？
SEAL系统常见错误及处理策略：
- **会话过期**：重新创建SessionKey并获取用户签名
- **权限不足**：检查访问条件，确认用户满足链上要求
- **签名验证失败**：重新请求用户签名，检查钱包地址
- **服务器无响应**：切换到其他密钥服务器，利用阈值机制
- **密钥验证失败**：可能是服务器返回了无效密钥，尝试其他服务器
- **解密失败**：检查密钥是否正确，数据是否完整

### Q14: SEAL系统的安全性如何保障？
SEAL系统的安全保障机制：
- **密码学基础**：基于成熟的椭圆曲线加密和IBE系统
- **链上验证**：权限逻辑在链上执行，不依赖服务器
- **阈值分布**：密钥分散在多个服务器，防止单点攻击
- **时间限制**：所有会话均有严格的时间限制
- **多重签名**：用户签名和会话签名双重验证
- **零状态**：服务器不保存会话状态，降低攻击面

### Q15: SEAL与链上密钥系统的区别是什么？
SEAL与纯链上密钥系统的比较：
- **性能**：SEAL避免了链上解密的高成本，更高效
- **大数据支持**：可处理大型加密数据，不受链上存储限制
- **灵活性**：仅访问控制在链上，加密操作在链下执行
- **隐私性**：加密数据和解密过程完全在链下，增强隐私
- **可扩展性**：可支持更复杂的加密方案和大量数据
- **成本效益**：大幅降低链上交易成本，同时保持链上验证的安全性

这些问答涵盖了SEAL系统的核心概念、技术选择、架构特点和实际应用，为开发者和用户提供全面的参考指南。
