import { SealClient, SessionKey, NoAccessError, EncryptedObject } from '@mysten/seal';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import React from 'react';

/**
 * Move调用构造器类型
 * 用于构建验证访问权限的交易
 */
export type MoveCallConstructor = (tx: Transaction, id: string) => void;

/**
 * 下载并解密加密的Blob
 * 
 * 此函数执行以下操作：
 * 1. 从Walrus聚合器下载加密的Blob
 * 2. 提取所有Blob的ID并构建批量密钥获取请求
 * 3. 使用SEAL客户端和会话密钥获取解密密钥
 * 4. 解密所有Blob并显示内容
 * 
 * @param blobIds - 要下载和解密的Blob ID列表
 * @param sessionKey - 用于验证的会话密钥
 * @param suiClient - Sui客户端实例
 * @param sealClient - SEAL客户端实例
 * @param moveCallConstructor - 构建交易的函数
 * @param setError - 设置错误信息的函数
 * @param setDecryptedFileUrls - 设置解密后文件URL的函数
 * @param setIsDialogOpen - 设置对话框状态的函数
 * @param setReloadKey - 设置重新加载键的函数
 */
export const downloadAndDecrypt = async (
  blobIds: string[],
  sessionKey: SessionKey,
  suiClient: SuiClient,
  sealClient: SealClient,
  moveCallConstructor: (tx: Transaction, id: string) => void,
  setError: (error: string | null) => void,
  setDecryptedFileUrls: (urls: string[]) => void,
  setIsDialogOpen: (open: boolean) => void,
  setReloadKey: (updater: (prev: number) => number) => void,
) => {
  // 可用的Walrus聚合器列表
  const aggregators = ['aggregator2', 'aggregator3'];
  
  // 并行下载所有文件（忽略错误）
  const downloadResults = await Promise.all(
    blobIds.map(async (blobId) => {
      try {
        // 设置请求超时
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        
        // 随机选择一个聚合器
        const randomAggregator = aggregators[Math.floor(Math.random() * aggregators.length)];
        const aggregatorUrl = `/${randomAggregator}/v1/blobs/${blobId}`;
        
        // 发送请求下载加密的Blob
        const response = await fetch(aggregatorUrl, { signal: controller.signal });
        clearTimeout(timeout);
        if (!response.ok) {
          return null;
        }
        return await response.arrayBuffer();
      } catch (err) {
        console.error(`Blob ${blobId} cannot be retrieved from Walrus`, err);
        return null;
      }
    }),
  );

  // 过滤掉下载失败的结果
  const validDownloads = downloadResults.filter((result): result is ArrayBuffer => result !== null);
  console.log('validDownloads count', validDownloads.length);

  // 检查是否有有效的下载结果
  if (validDownloads.length === 0) {
    const errorMsg =
      'Cannot retrieve files from this Walrus aggregator, try again (a randomly selected aggregator will be used). Files uploaded more than 1 epoch ago have been deleted from Walrus.';
    console.error(errorMsg);
    setError(errorMsg);
    return;
  }

  // 批量获取密钥（每批最多10个）
  for (let i = 0; i < validDownloads.length; i += 10) {
    const batch = validDownloads.slice(i, i + 10);
    // 从每个加密对象中提取ID
    const ids = batch.map((enc) => EncryptedObject.parse(new Uint8Array(enc)).id);
    
    // 构建验证交易
    const tx = new Transaction();
    ids.forEach((id) => moveCallConstructor(tx, id));
    const txBytes = await tx.build({ client: suiClient, onlyTransactionKind: true });
    
    try {
      // 使用SEAL客户端获取解密密钥
      await sealClient.fetchKeys({ ids, txBytes, sessionKey, threshold: 2 });
    } catch (err) {
      console.log(err);
      const errorMsg =
        err instanceof NoAccessError
          ? 'No access to decryption keys'
          : 'Unable to decrypt files, try again';
      console.error(errorMsg, err);
      setError(errorMsg);
      return;
    }
  }

  // 依次解密每个文件
  const decryptedFileUrls: string[] = [];
  for (const encryptedData of validDownloads) {
    // 解析加密对象ID
    const fullId = EncryptedObject.parse(new Uint8Array(encryptedData)).id;
    
    // 构建验证交易
    const tx = new Transaction();
    moveCallConstructor(tx, fullId);
    const txBytes = await tx.build({ client: suiClient, onlyTransactionKind: true });
    
    try {
      // 注意：所有密钥在上一步已获取，这里只进行本地解密
      const decryptedFile = await sealClient.decrypt({
        data: new Uint8Array(encryptedData),
        sessionKey,
        txBytes,
      });
      
      // 创建Blob URL供显示
      const blob = new Blob([decryptedFile], { type: 'image/jpg' });
      decryptedFileUrls.push(URL.createObjectURL(blob));
    } catch (err) {
      console.log(err);
      const errorMsg =
        err instanceof NoAccessError
          ? 'No access to decryption keys'
          : 'Unable to decrypt files, try again';
      console.error(errorMsg, err);
      setError(errorMsg);
      return;
    }
  }

  // 如果有解密成功的文件，更新UI
  if (decryptedFileUrls.length > 0) {
    setDecryptedFileUrls(decryptedFileUrls);
    setIsDialogOpen(true);
    setReloadKey((prev) => prev + 1);
  }
};

/**
 * 生成对象浏览器链接的React元素
 * 
 * @param id - 对象ID
 * @returns 包含链接的React元素
 */
export const getObjectExplorerLink = (id: string): React.ReactElement => {
  return React.createElement(
    'a',
    {
      href: `https://testnet.suivision.xyz/object/${id}`,
      target: '_blank',
      rel: 'noopener noreferrer',
      style: { textDecoration: 'underline' },
    },
    id.slice(0, 10) + '...',
  );
};
