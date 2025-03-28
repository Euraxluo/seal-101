 /**
 * 加密系统错误类型定义
 * 为不同类型的错误提供具体类，方便错误处理
 */

// 基础错误类
export class CryptoGameError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'CryptoGameError';
    }
  }
  
  // 网络错误
  export class NetworkError extends CryptoGameError {
    constructor(message: string = '网络连接错误') {
      super(message);
      this.name = 'NetworkError';
    }
  }
  
  // 权限错误
  export class PermissionError extends CryptoGameError {
    constructor(message: string = '没有解密权限') {
      super(message);
      this.name = 'PermissionError';
    }
  }
  
  // 卡牌错误
  export class CardError extends CryptoGameError {
    constructor(message: string = '卡牌操作错误') {
      super(message);
      this.name = 'CardError';
    }
  }
  
  // 会话错误
  export class SessionError extends CryptoGameError {
    constructor(message: string = '会话无效或过期') {
      super(message);
      this.name = 'SessionError';
    }
  }
  
  // 密钥服务器错误
  export class KeyServerError extends CryptoGameError {
    constructor(message: string = '密钥服务器错误') {
      super(message);
      this.name = 'KeyServerError';
    }
  }
  
  // 阈值错误
  export class ThresholdError extends CryptoGameError {
    constructor(message: string = '阈值配置错误') {
      super(message);
      this.name = 'ThresholdError';
    }
  }