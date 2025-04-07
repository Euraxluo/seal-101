// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react';
import { useSignPersonalMessage, useSuiClient } from '@mysten/dapp-kit';
import { useNetworkVariable } from './networkConfig';
import { AlertDialog, Button, Card, Dialog, Flex, Grid } from '@radix-ui/themes';
import { fromHex } from '@mysten/sui/utils';
import { Transaction } from '@mysten/sui/transactions';
import { SuiClient } from '@mysten/sui/client';
import { getAllowlistedKeyServers, SealClient, SessionKey } from '@mysten/seal';
import { useParams } from 'react-router-dom';
import { downloadAndDecrypt, getObjectExplorerLink, MoveCallConstructor } from './utils';

/**
 * 会话密钥TTL（分钟）
 */
const TTL_MIN = 10;

/**
 * 许可名单数据接口
 */
export interface FeedData {
  allowlistId: string;     // 许可名单ID
  allowlistName: string;   // 许可名单名称
  blobIds: string[];       // 关联的Blob ID列表
}

/**
 * 构造Move调用参数
 * 
 * 创建用于许可名单访问验证的交易调用
 * 
 * @param packageId - 包ID
 * @param allowlistId - 许可名单ID
 * @returns 交易构造函数
 */
function constructMoveCall(packageId: string, allowlistId: string): MoveCallConstructor {
  return (tx: Transaction, id: string) => {
    tx.moveCall({
      target: `${packageId}::allowlist::seal_approve`,
      arguments: [tx.pure.vector('u8', fromHex(id)), tx.object(allowlistId)],
    });
  };
}

/**
 * Feeds组件 - 显示和处理许可名单关联的加密文件
 * 
 * 主要功能：
 * 1. 获取许可名单信息和关联的Blob ID
 * 2. 创建会话密钥并签名
 * 3. 使用SEAL下载并解密文件
 * 4. 显示解密后的图片
 */
const Feeds: React.FC<{ suiAddress: string }> = ({ suiAddress }) => {
  // 初始化Sui和SEAL客户端
  const suiClient = useSuiClient();
  const client = new SealClient({
    suiClient,
    serverObjectIds: getAllowlistedKeyServers('testnet'),
    verifyKeyServers: false,
  });
  const packageId = useNetworkVariable('packageId');

  // 状态管理
  const [feed, setFeed] = useState<FeedData>();                      // 许可名单数据
  const [decryptedFileUrls, setDecryptedFileUrls] = useState<string[]>([]);  // 已解密文件URL
  const [error, setError] = useState<string | null>(null);           // 错误信息
  const [currentSessionKey, setCurrentSessionKey] = useState<SessionKey | null>(null);  // 当前会话密钥
  const { id } = useParams();                                        // 从URL获取许可名单ID
  const [isDialogOpen, setIsDialogOpen] = useState(false);           // 对话框状态
  const [reloadKey, setReloadKey] = useState(0);                     // 刷新键

  // 签名钩子
  const { mutate: signPersonalMessage } = useSignPersonalMessage();

  useEffect(() => {
    // 立即调用getFeed获取数据
    getFeed();

    // 设置3秒轮询间隔
    const intervalId = setInterval(() => {
      getFeed();
    }, 3000);

    // 组件卸载时清除定时器
    return () => clearInterval(intervalId);
  }, [id, suiClient, packageId]); // 添加所有getFeed使用的依赖项

  /**
   * 获取许可名单信息和关联的Blob ID
   */
  async function getFeed() {
    // 获取许可名单对象信息
    const allowlist = await suiClient.getObject({
      id: id!,
      options: { showContent: true },
    });
    
    // 获取关联到许可名单的所有动态字段（Blob ID）
    const encryptedObjects = await suiClient
      .getDynamicFields({
        parentId: id!,
      })
      .then((res) => res.data.map((obj) => obj.name.value as string));
    
    // 从响应中提取许可名单字段
    const fields = (allowlist.data?.content as { fields: any })?.fields || {};
    
    // 构建Feed数据
    const feedData = {
      allowlistId: id!,
      allowlistName: fields?.name,
      blobIds: encryptedObjects,
    };
    setFeed(feedData);
  }

  /**
   * 查看加密文件
   * 
   * 处理下载和解密过程，包括：
   * 1. 检查是否有可用的会话密钥
   * 2. 如果没有，创建新的会话密钥并签名
   * 3. 下载和解密加密的Blob
   * 
   * @param blobIds - 要解密的Blob ID列表
   * @param allowlistId - 许可名单ID
   */
  const onView = async (blobIds: string[], allowlistId: string) => {
    // 检查是否有有效的会话密钥
    if (
      currentSessionKey &&
      !currentSessionKey.isExpired() &&
      currentSessionKey.getAddress() === suiAddress
    ) {
      // 使用现有会话密钥
      const moveCallConstructor = constructMoveCall(packageId, allowlistId);
      downloadAndDecrypt(
        blobIds,
        currentSessionKey,
        suiClient,
        client,
        moveCallConstructor,
        setError,
        setDecryptedFileUrls,
        setIsDialogOpen,
        setReloadKey,
      );
      return;
    }

    // 清除旧的会话密钥
    setCurrentSessionKey(null);

    // 创建新的会话密钥
    const sessionKey = new SessionKey({
      address: suiAddress,
      packageId,
      ttlMin: TTL_MIN,
    });

    try {
      // 签名个人消息以授权会话密钥
      signPersonalMessage(
        {
          message: sessionKey.getPersonalMessage(),
        },
        {
          onSuccess: async (result) => {
            // 设置个人消息签名
            await sessionKey.setPersonalMessageSignature(result.signature);
            // 构造Move调用
            const moveCallConstructor = await constructMoveCall(packageId, allowlistId);
            // 下载并解密
            await downloadAndDecrypt(
              blobIds,
              sessionKey,
              suiClient,
              client,
              moveCallConstructor,
              setError,
              setDecryptedFileUrls,
              setIsDialogOpen,
              setReloadKey,
            );
            // 保存当前会话密钥以供重用
            setCurrentSessionKey(sessionKey);
          },
        },
      );
    } catch (error: any) {
      console.error('Error:', error);
    }
  };

  // 组件渲染
  return (
    <Card>
      <h2 style={{ marginBottom: '1rem' }}>
        Files for Allowlist {feed?.allowlistName} (ID{' '}
        {feed?.allowlistId && getObjectExplorerLink(feed.allowlistId)})
      </h2>
      {feed === undefined ? (
        <p>No files found for this allowlist.</p>
      ) : (
        <Grid columns="2" gap="3">
          <Card key={feed!.allowlistId}>
            <Flex direction="column" align="start" gap="2">
              {feed!.blobIds.length === 0 ? (
                <p>No files found for this allowlist.</p>
              ) : (
                <Dialog.Root open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                  <Dialog.Trigger>
                    <Button onClick={() => onView(feed!.blobIds, feed!.allowlistId)}>
                      Download And Decrypt All Files
                    </Button>
                  </Dialog.Trigger>
                  {decryptedFileUrls.length > 0 && (
                    <Dialog.Content maxWidth="450px" key={reloadKey}>
                      <Dialog.Title>View all files retrieved from Walrus</Dialog.Title>
                      <Flex direction="column" gap="2">
                        {decryptedFileUrls.map((decryptedFileUrl, index) => (
                          <div key={index}>
                            <img src={decryptedFileUrl} alt={`Decrypted image ${index + 1}`} />
                          </div>
                        ))}
                      </Flex>
                      <Flex gap="3" mt="4" justify="end">
                        <Dialog.Close>
                          <Button
                            variant="soft"
                            color="gray"
                            onClick={() => setDecryptedFileUrls([])}
                          >
                            Close
                          </Button>
                        </Dialog.Close>
                      </Flex>
                    </Dialog.Content>
                  )}
                </Dialog.Root>
              )}
            </Flex>
          </Card>
        </Grid>
      )}
      <AlertDialog.Root open={!!error} onOpenChange={() => setError(null)}>
        <AlertDialog.Content maxWidth="450px">
          <AlertDialog.Title>Error</AlertDialog.Title>
          <AlertDialog.Description size="2">{error}</AlertDialog.Description>

          <Flex gap="3" mt="4" justify="end">
            <AlertDialog.Action>
              <Button variant="solid" color="gray" onClick={() => setError(null)}>
                Close
              </Button>
            </AlertDialog.Action>
          </Flex>
        </AlertDialog.Content>
      </AlertDialog.Root>
    </Card>
  );
};

export default Feeds;
