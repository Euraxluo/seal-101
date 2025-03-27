/**
 * 生成密钥对脚本
 * 
 * 用法：
 * npx ts-node -T src/scripts/generate-keypair.ts
 */

import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { toB64 } from '@mysten/sui/utils';

// 创建新的密钥对
const keypair = new Ed25519Keypair();
const publicKey = keypair.getPublicKey();

console.log('=== 新生成的密钥对 ===');
console.log('地址:', publicKey.toSuiAddress());
console.log('公钥:', publicKey.toBase64());

// 注意：在新版本的@mysten/sui中，无法直接访问私钥
// 这里仅作为示例，实际使用时应当使用安全的方式处理密钥
console.log('\n使用示例:');
console.log(`
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { fromB64 } from '@mysten/sui/utils';

// 从助记词创建密钥对
const keypair = Ed25519Keypair.deriveKeypair("您的助记词");

// 或者使用fromSecretKey方法
// const privateKeyBytes = fromB64("您的Base64编码私钥");
// const keypair = Ed25519Keypair.fromSecretKey(privateKeyBytes);
`);

console.log('\n注意: 请妥善保管私钥和助记词，不要分享给他人！'); 