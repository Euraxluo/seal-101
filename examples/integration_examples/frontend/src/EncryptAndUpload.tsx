// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import React, { useState } from 'react';
import { Transaction } from '@mysten/sui/transactions';
import { useNetworkVariable } from './networkConfig';
import { useSignAndExecuteTransaction, useSuiClient } from '@mysten/dapp-kit';
import { Button, Card, Flex, Spinner, Text } from '@radix-ui/themes';
import { getAllowlistedKeyServers, SealClient } from '@mysten/seal';
import { fromHex, toHex } from '@mysten/sui/utils';

/**
 * 数据对象类型，表示上传到Walrus的加密数据信息
 */
export type Data = {
  status: string;        // 状态：新创建或已认证
  blobId: string;        // Blob的唯一标识符
  endEpoch: string;      // Blob存储的结束epoch
  suiRefType: string;    // Sui引用类型
  suiRef: string;        // Sui引用ID
  suiBaseUrl: string;    // Sui浏览器基础URL
  blobUrl: string;       // Blob访问URL
  suiUrl: string;        // Sui对象URL
  isImage: string;       // 是否为图片
};

/**
 * WalrusUpload组件属性接口
 */
interface WalrusUploadProps {
  policyObject: string;  // 访问策略对象ID，可以是许可名单或订阅服务ID
  cap_id: string;        // 管理员权限凭证ID
  moduleName: string;    // 模块名称，可以是"allowlist"或"subscription"
}

/**
 * Walrus服务定义，包含服务ID、名称和API端点
 */
type WalrusService = {
  id: string;              // 服务ID
  name: string;            // 服务名称
  publisherUrl: string;    // 发布者API端点
  aggregatorUrl: string;   // 聚合器API端点
};

/**
 * 加密并上传文件组件
 * 
 * 该组件实现了以下功能：
 * 1. 选择Walrus服务
 * 2. 上传并使用SEAL进行加密
 * 3. 将加密数据存储到Walrus服务
 * 4. 将Blob ID关联到访问策略对象（许可名单或订阅服务）
 */
export function WalrusUpload({ policyObject, cap_id, moduleName }: WalrusUploadProps) {
  // 状态管理
  const [file, setFile] = useState<File | null>(null);                   // 选择的文件
  const [info, setInfo] = useState<Data | null>(null);                   // 上传后的数据信息
  const [isUploading, setIsUploading] = useState<boolean>(false);        // 是否正在上传
  const [selectedService, setSelectedService] = useState<string>('service1'); // 选择的Walrus服务

  // 常量定义
  const SUI_VIEW_TX_URL = `https://suiscan.xyz/testnet/tx`;              // 交易查看URL
  const SUI_VIEW_OBJECT_URL = `https://suiscan.xyz/testnet/object`;      // 对象查看URL

  const NUM_EPOCH = 1;                                                   // 存储的epoch数量
  const packageId = useNetworkVariable('packageId');                      // 包ID
  const suiClient = useSuiClient();                                      // Sui客户端
  
  // 初始化SEAL客户端
  const client = new SealClient({
    suiClient,
    serverObjectIds: getAllowlistedKeyServers('testnet'),                // 获取所有允许的密钥服务器
    verifyKeyServers: false,                                             // 不验证密钥服务器
  });

  // Walrus服务列表
  const services: WalrusService[] = [
    {
      id: 'service2',
      name: 'staketab.org',
      publisherUrl: '/publisher2',
      aggregatorUrl: '/aggregator2',
    },
    {
      id: 'service3',
      name: 'redundex.com',
      publisherUrl: '/publisher3',
      aggregatorUrl: '/aggregator3',
    },
  ];

  /**
   * 获取聚合器URL
   * @param path - API路径
   * @returns 完整的聚合器URL
   */
  function getAggregatorUrl(path: string): string {
    const service = services.find((s) => s.id === selectedService);
    const cleanPath = path.replace(/^\/+/, '').replace(/^v1\//, '');
    return `${service?.aggregatorUrl}/v1/${cleanPath}`;
  }

  /**
   * 获取发布者URL
   * @param path - API路径
   * @returns 完整的发布者URL
   */
  function getPublisherUrl(path: string): string {
    const service = services.find((s) => s.id === selectedService);
    const cleanPath = path.replace(/^\/+/, '').replace(/^v1\//, '');
    return `${service?.publisherUrl}/v1/${cleanPath}`;
  }

  // 使用Sui交易签名和执行钩子
  const { mutate: signAndExecute } = useSignAndExecuteTransaction({
    execute: async ({ bytes, signature }) =>
      await suiClient.executeTransactionBlock({
        transactionBlock: bytes,
        signature,
        options: {
          showRawEffects: true,
          showEffects: true,
        },
      }),
  });

  /**
   * 处理文件选择事件
   * @param event - 文件选择事件
   */
  const handleFileChange = (event: any) => {
    const file = event.target.files[0];
    // 检查文件大小，最大10 MiB
    if (file.size > 10 * 1024 * 1024) {
      alert('File size must be less than 10 MiB');
      return;
    }
    // 检查文件类型，仅支持图片
    if (!file.type.startsWith('image/')) {
      alert('Only image files are allowed');
      return;
    }
    setFile(file);
    setInfo(null);
  };

  /**
   * 处理提交事件
   * 读取文件，使用SEAL加密，并上传到Walrus
   */
  const handleSubmit = () => {
    setIsUploading(true);
    if (file) {
      const reader = new FileReader();
      reader.onload = async function (event) {
        if (event.target && event.target.result) {
          const result = event.target.result;
          if (result instanceof ArrayBuffer) {
            // 生成随机nonce，构建加密ID
            const nonce = crypto.getRandomValues(new Uint8Array(5));
            const policyObjectBytes = fromHex(policyObject);
            const id = toHex(new Uint8Array([...policyObjectBytes, ...nonce]));
            
            // 使用SEAL客户端进行加密
            const { encryptedObject: encryptedBytes } = await client.encrypt({
              threshold: 2,                // 解密所需的最小密钥服务器数量
              packageId,                   // 包ID
              id,                          // 加密ID，包含策略对象ID和随机nonce
              data: new Uint8Array(result), // 原始数据
            });
            
            // 存储加密的Blob到Walrus
            const storageInfo = await storeBlob(encryptedBytes);
            displayUpload(storageInfo.info, file.type);
            setIsUploading(false);
          } else {
            console.error('Unexpected result type:', typeof result);
            setIsUploading(false);
          }
        }
      };
      reader.readAsArrayBuffer(file);
    } else {
      console.error('No file selected');
    }
  };

  /**
   * 处理上传结果并显示信息
   * @param storage_info - 存储信息
   * @param media_type - 媒体类型
   */
  const displayUpload = (storage_info: any, media_type: any) => {
    let info;
    if ('alreadyCertified' in storage_info) {
      // 处理已认证的情况
      info = {
        status: 'Already certified',
        blobId: storage_info.alreadyCertified.blobId,
        endEpoch: storage_info.alreadyCertified.endEpoch,
        suiRefType: 'Previous Sui Certified Event',
        suiRef: storage_info.alreadyCertified.event.txDigest,
        suiBaseUrl: SUI_VIEW_TX_URL,
        blobUrl: getAggregatorUrl(`/v1/blobs/${storage_info.alreadyCertified.blobId}`),
        suiUrl: `${SUI_VIEW_OBJECT_URL}/${storage_info.alreadyCertified.event.txDigest}`,
        isImage: media_type.startsWith('image'),
      };
    } else if ('newlyCreated' in storage_info) {
      // 处理新创建的情况
      info = {
        status: 'Newly created',
        blobId: storage_info.newlyCreated.blobObject.blobId,
        endEpoch: storage_info.newlyCreated.blobObject.storage.endEpoch,
        suiRefType: 'Associated Sui Object',
        suiRef: storage_info.newlyCreated.blobObject.id,
        suiBaseUrl: SUI_VIEW_OBJECT_URL,
        blobUrl: getAggregatorUrl(`/v1/blobs/${storage_info.newlyCreated.blobObject.blobId}`),
        suiUrl: `${SUI_VIEW_OBJECT_URL}/${storage_info.newlyCreated.blobObject.id}`,
        isImage: media_type.startsWith('image'),
      };
    } else {
      throw Error('Unhandled successful response!');
    }
    setInfo(info);
  };

  /**
   * 将加密数据存储到Walrus服务
   * @param encryptedData - 加密后的数据
   * @returns 存储结果信息
   */
  const storeBlob = (encryptedData: Uint8Array) => {
    return fetch(`${getPublisherUrl(`/v1/blobs?epochs=${NUM_EPOCH}`)}`, {
      method: 'PUT',
      body: encryptedData,
    }).then((response) => {
      if (response.status === 200) {
        return response.json().then((info) => {
          return { info };
        });
      } else {
        alert('Error publishing the blob on Walrus, please select a different Walrus service.');
        setIsUploading(false);
        throw new Error('Something went wrong when storing the blob!');
      }
    });
  };

  /**
   * 在链上发布Blob ID，将其关联到访问策略对象
   * @param wl_id - 策略对象ID
   * @param cap_id - 管理员权限凭证ID
   * @param moduleName - 模块名称
   */
  async function handlePublish(wl_id: string, cap_id: string, moduleName: string) {
    // 创建交易
    const tx = new Transaction();
    tx.moveCall({
      target: `${packageId}::${moduleName}::publish`,
      arguments: [tx.object(wl_id), tx.object(cap_id), tx.pure.string(info!.blobId)],
    });

    tx.setGasBudget(10000000);
    
    // 签名并执行交易
    signAndExecute(
      {
        transaction: tx,
      },
      {
        onSuccess: async (result) => {
          console.log('res', result);
          alert('Blob attached successfully, now share the link or upload more.');
        },
      },
    );
  }

  // 组件渲染
  return (
    <Card>
      <Flex direction="column" gap="2" align="start">
        <Flex gap="2" align="center">
          <Text>Select Walrus service:</Text>
          <select
            value={selectedService}
            onChange={(e) => setSelectedService(e.target.value)}
            aria-label="Select Walrus service"
          >
            {services.map((service) => (
              <option key={service.id} value={service.id}>
                {service.name}
              </option>
            ))}
          </select>
        </Flex>
        <input
          type="file"
          onChange={handleFileChange}
          accept="image/*"
          aria-label="Choose image file to upload"
        />
        <p>File size must be less than 10 MiB. Only image files are allowed.</p>
        <Button
          onClick={() => {
            handleSubmit();
          }}
          disabled={file === null}
        >
          First step: Encrypt and upload to Walrus
        </Button>
        {isUploading && (
          <div role="status">
            <Spinner className="animate-spin" aria-label="Uploading" />
            <span>
              Uploading to Walrus (may take a few seconds, retrying with different service is
              possible){' '}
            </span>
          </div>
        )}

        {info && file && (
          <div id="uploaded-blobs" role="region" aria-label="Upload details">
            <dl>
              <dt>Status:</dt>
              <dd>{info.status}</dd>
              <dd>
                <a
                  href={info.blobUrl}
                  style={{ textDecoration: 'underline' }}
                  download
                  onClick={(e) => {
                    e.preventDefault();
                    window.open(info.blobUrl, '_blank', 'noopener,noreferrer');
                  }}
                  aria-label="Download encrypted blob"
                >
                  Encrypted blob
                </a>
              </dd>
              <dd>
                <a
                  href={info.suiUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ textDecoration: 'underline' }}
                  aria-label="View Sui object details"
                >
                  Sui Object
                </a>
              </dd>
            </dl>
          </div>
        )}
      </Flex>
    </Card>
  );
}

export default WalrusUpload;
