# Seal 项目

本项目包含三个核心模块：

1. `crypto` - 密码学核心库
2. `key-server` - 密钥服务器实现
3. `seal-cli` - 命令行工具

所有模块都支持编译为WebAssembly (WASM)。

## 构建指南

### 常规构建

```bash
# 构建所有模块
cargo build

# 构建特定模块
cargo build -p crypto
cargo build -p key-server
cargo build -p seal-cli

# 构建发布版本
cargo build --release
```

### WebAssembly 构建

#### 安装工具链

首先，需要安装WASM编译工具：

```bash
# 安装wasm32编译目标
rustup target add wasm32-unknown-unknown

# 安装wasm-bindgen-cli
cargo install wasm-bindgen-cli
```

#### 编译为WASM

```bash
# 编译crypto模块为WASM
cargo build --target wasm32-unknown-unknown --profile wasm-release --features wasm -p crypto

# 编译seal-cli模块为WASM
cargo build --target wasm32-unknown-unknown --profile wasm-release --features wasm -p seal-cli

# 编译key-server模块为WASM
cargo build --target wasm32-unknown-unknown --profile wasm-release --features wasm -p key-server
```

#### 生成JavaScript绑定

编译完成后，为WASM文件生成JavaScript绑定：

```bash
# 生成crypto模块的JavaScript绑定
wasm-bindgen --target web --out-dir ./target/wasm-bindgen/crypto ./target/wasm32-unknown-unknown/wasm-release/crypto.wasm

# 生成seal-cli模块的JavaScript绑定
wasm-bindgen --target web --out-dir ./target/wasm-bindgen/seal-cli ./target/wasm32-unknown-unknown/wasm-release/seal_cli.wasm

# 生成key-server模块的JavaScript绑定
wasm-bindgen --target web --out-dir ./target/wasm-bindgen/key-server ./target/wasm32-unknown-unknown/wasm-release/key_server.wasm
```

## 使用WASM模块

编译后的WASM模块及其JavaScript绑定可以在Web应用中使用：

```html
<script type="module">
  import init, { example_wasm_function } from './target/wasm-bindgen/crypto/crypto.js';

  async function run() {
    // 初始化WASM模块
    await init();
    
    // 调用WASM函数
    const result = example_wasm_function("测试输入");
    console.log(result);
  }

  run();
</script>
```

## 项目结构

```
crates/
├── crypto/           # 密码学核心库
├── key-server/       # 密钥服务器
├── seal-cli/         # 命令行工具
├── Cargo.toml        # 工作区配置
├── rust-toolchain    # Rust 工具链版本
└── deny.toml         # 依赖审核配置
```