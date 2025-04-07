// // Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * 可编程交易块(PTB)验证模块
 * 
 * 本模块实现了对可编程交易块(Programmable Transaction Block)的验证逻辑。
 * PTB是Sui上的交易格式，在Seal密钥管理系统中，客户端通过PTB请求密钥。
 * 
 * 该模块确保PTB满足特定的安全要求，例如：
 * 1. 包含必要的输入参数
 * 2. 只调用seal_approve开头的函数
 * 3. 使用正确的包ID
 * 4. 包含有效的密钥ID
 */

use crate::errors::InternalError;
use crate::KeyId;
use crypto::create_full_id;
use sui_sdk::types::transaction::{Argument, CallArg, Command, ProgrammableTransaction};
use sui_types::base_types::ObjectID;
use sui_types::transaction::ProgrammableMoveCall;
use tracing::debug;

/**
 * 有效的可编程交易块
 * 
 * 这个结构体封装了经过验证的可编程交易块，确保它符合Seal密钥服务器的要求。
 * 此结构有助于防止恶意请求，并确保仅处理符合预期格式的交易。
 */
pub struct ValidPtb(ProgrammableTransaction);

/**
 * 从原始PTB转换为ValidPtb的实现
 * 
 * 执行一系列验证检查，确保PTB满足以下条件：
 * 1. 包含至少一个输入和一个命令
 * 2. 第一个命令是MoveCall
 * 3. 所有命令都是MoveCall类型
 * 4. 每个MoveCall的第一个参数是非空的密钥ID
 * 5. 所有被调用的函数以seal_approve开头
 * 6. 所有命令使用相同的包ID
 */
impl TryFrom<ProgrammableTransaction> for ValidPtb {
    type Error = InternalError;

    fn try_from(ptb: ProgrammableTransaction) -> Result<Self, Self::Error> {
        debug!("Creating vptb from: {:?}", ptb);

        // 限制：PTB必须至少有一个输入和一个命令
        if ptb.inputs.is_empty() || ptb.commands.is_empty() {
            debug!("Invalid PTB: {:?}", ptb);
            return Err(InternalError::InvalidPTB);
        }

        // 检查上面确认至少有一个命令
        let Command::MoveCall(first_cmd) = &ptb.commands[0] else {
            debug!("Invalid PTB: {:?}", ptb);
            return Err(InternalError::InvalidPTB);
        };
        let pkg_id = first_cmd.package;

        for cmd in &ptb.commands {
            // 限制：所有命令必须是MoveCall类型
            let Command::MoveCall(cmd) = &cmd else {
                debug!("Invalid PTB first command: {:?}", cmd);
                return Err(InternalError::InvalidPTB);
            };

            // 限制：MoveCall的第一个参数必须是非空ID
            // 限制：调用的函数必须以seal_approve开头
            // 限制：所有命令必须使用相同的包ID
            if cmd.arguments.is_empty()
                || get_key_id(&ptb, cmd).is_err()
                || !cmd.function.starts_with("seal_approve")
                || cmd.package != pkg_id
            {
                debug!("Invalid PTB command: {:?}", cmd);
                return Err(InternalError::InvalidPTB);
            }
        }

        // TODO: 健全性检查 - 不可变对象

        Ok(ValidPtb(ptb))
    }
}

/**
 * 从MoveCall中提取密钥ID
 * 
 * 从命令的第一个参数中提取密钥ID，这个ID将用于IBE加密系统中。
 * 
 * 参数:
 * @param ptb - 可编程交易块
 * @param cmd - 要从中提取ID的可编程Move调用
 * 
 * 返回:
 * 成功时返回密钥ID，失败时返回错误
 */
fn get_key_id(
    ptb: &ProgrammableTransaction,
    cmd: &ProgrammableMoveCall,
) -> Result<KeyId, InternalError> {
    if cmd.arguments.is_empty() {
        return Err(InternalError::InvalidPTB);
    }
    let Argument::Input(arg_idx) = cmd.arguments[0] else {
        return Err(InternalError::InvalidPTB);
    };
    let CallArg::Pure(id) = &ptb.inputs[arg_idx as usize] else {
        return Err(InternalError::InvalidPTB);
    };
    bcs::from_bytes(id).map_err(|_| InternalError::InvalidPTB)
}

impl ValidPtb {
    /**
     * 获取所有内部密钥ID
     * 
     * 返回PTB中所有seal_approve调用使用的密钥ID，不包含包ID前缀。
     * 
     * 返回:
     * 密钥ID向量
     */
    pub fn inner_ids(&self) -> Vec<KeyId> {
        self.0
            .commands
            .iter()
            .map(|cmd| {
                let Command::MoveCall(cmd) = cmd else {
                    unreachable!()
                };
                get_key_id(&self.0, cmd).expect("checked above")
            })
            .collect()
    }

    /**
     * 获取PTB使用的包ID
     * 
     * 返回:
     * 包ID
     */
    pub fn pkg_id(&self) -> ObjectID {
        let Command::MoveCall(cmd) = &self.0.commands[0] else {
            unreachable!()
        };
        cmd.package
    }

    /**
     * 获取带包ID前缀的完整密钥ID
     * 
     * 将每个内部ID与第一个版本的包ID组合，形成完整的密钥ID。
     * 这对于密钥的正确加密和检索至关重要。
     * 
     * 参数:
     * @param first_pkg_id - 第一个版本的包ID
     * 
     * 返回:
     * 完整密钥ID向量
     */
    pub fn full_ids(&self, first_pkg_id: &ObjectID) -> Vec<KeyId> {
        self.inner_ids()
            .iter()
            .map(|inner_id| create_full_id(&first_pkg_id.into_bytes(), inner_id))
            .collect()
    }

    /**
     * 获取原始的可编程交易块
     * 
     * 返回:
     * 原始PTB引用
     */
    pub fn ptb(&self) -> &ProgrammableTransaction {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_sdk::types::base_types::SuiAddress;
    use sui_types::base_types::ObjectID;
    use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
    use sui_types::Identifier;

    #[test]
    fn test_valid() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let id = vec![1u8, 2, 3, 4];
        let id_caller = builder.pure(id.clone()).unwrap();
        let pkgid = ObjectID::random();
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve_x").unwrap(),
            vec![],
            vec![id_caller],
        );
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla2").unwrap(),
            Identifier::new("seal_approve_y").unwrap(),
            vec![],
            vec![id_caller],
        );
        let ptb = builder.finish();
        let valid_ptb = ValidPtb::try_from(ptb).unwrap();

        assert_eq!(valid_ptb.inner_ids(), vec![id.clone(), id]);
        assert_eq!(valid_ptb.pkg_id(), pkgid);
    }

    #[test]
    fn test_invalid_empty_ptb() {
        let builder = ProgrammableTransactionBuilder::new();
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB)
        );
    }

    #[test]
    fn test_invalid_no_inputs() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let pkgid = ObjectID::random();
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve").unwrap(),
            vec![],
            vec![],
        );
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB)
        );
    }

    #[test]
    fn test_invalid_non_move_call() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let sender = SuiAddress::random_for_testing_only();
        let caller = builder.pure(sender).unwrap();
        let id = vec![1u8, 2, 3, 4];
        let id_caller = builder.pure(id.clone()).unwrap();
        let pkgid = ObjectID::random();
        builder.programmable_move_call(
            pkgid,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve_x").unwrap(),
            vec![],
            vec![caller, id_caller],
        );
        // Add a transfer command instead of move call
        builder.transfer_sui(sender, Some(1));
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB)
        );
    }

    #[test]
    fn test_invalid_different_package_ids() {
        let mut builder = ProgrammableTransactionBuilder::new();
        let sender = SuiAddress::random_for_testing_only();
        let caller = builder.pure(sender).unwrap();
        let id = builder.pure(vec![1u8, 2, 3]).unwrap();
        let pkgid1 = ObjectID::random();
        let pkgid2 = ObjectID::random();
        builder.programmable_move_call(
            pkgid1,
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve").unwrap(),
            vec![],
            vec![caller, id],
        );
        builder.programmable_move_call(
            pkgid2, // Different package ID
            Identifier::new("bla").unwrap(),
            Identifier::new("seal_approve").unwrap(),
            vec![],
            vec![caller, id],
        );
        let ptb = builder.finish();
        assert_eq!(
            ValidPtb::try_from(ptb).err(),
            Some(InternalError::InvalidPTB)
        );
    }
}
