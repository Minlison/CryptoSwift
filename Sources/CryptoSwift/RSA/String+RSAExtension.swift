//
//  String+RSAExtension.swift
//  CryptoSwift
//
//  Created by MinLison on 2017/8/14.
//  Copyright © 2017年 Marcin Krzyzanowski. All rights reserved.
//

import Foundation

extension String {
    
    /// RSA 加密
    ///
    /// - Parameter public_key: 公钥(Base64编码)
    /// - Returns: 加密后的字符串
    public func rsa_encrypt(public_key : String) -> String? {
        
        do {
            let publicKey = try PublicKey(base64Encoded: public_key)
            let clear = try ClearMessage(string: self, using: .utf8)
            let encrypted = try clear.encrypted(with: publicKey, SwiftyRSAPadding: .PKCS1)
            return encrypted.base64String;
        } catch {
            print(error)
        }
        return nil
    }
    
    ///  RSA 解密
    ///  本身是经过 Base64 位编码后的字符串
    /// - Parameter private_key: 私钥(Base64编码)
    /// - Returns: 界面后的字符串
    public func rsa_decrypt(private_key : String ) -> String? {
        do {
            let privateKey = try PrivateKey(base64Encoded: private_key);
            let encryptMessage = try EncryptedMessage(base64Encoded: self);
            return try encryptMessage.decrypted(with: privateKey, padding: .PKCS1).string(encoding: .utf8);
        } catch {
            print(error);
        }
        return nil
    }
}
