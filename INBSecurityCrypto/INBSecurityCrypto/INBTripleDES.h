//
//  INBTripleDES.h
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
/**
 *  TripleDES，俗称3DES。3DES加解密，使用CBC及PKCS7Padding。
 */
@interface INBTripleDES : NSObject
@property (nonatomic, copy, readonly, nullable) NSData *key;
@property (nonatomic, copy, readonly, nullable) NSData *iv;
+ (nonnull instancetype)sharedINBTripleDES;
/**
 *  更新密钥。密钥大小为kCCKeySize3DES（24）字节。
 */
- (void)updateKey;
/**
 *  更新初始化向量。IV大小为kCCBlockSize3DES（8）字节。
 */
- (void)updateIV;
/**
 *  3DES加密
 *
 *  @param plainData 待加密数据（明文数据）
 *
 *  @return 加密后的数据（密文数据）
 */
- (NSData * _Nullable)tripleDESEncrypt:(NSData * _Nonnull)plainData;
/**
 *  3DES解密
 *
 *  @param cipherData 待解密数据（密文数据）
 *
 *  @return 解密后的数据（明文数据）
 */
- (NSData * _Nullable)tripleDESDecrypt:(NSData * _Nonnull)cipherData;
/**
 *  加解密。当需要使用指定的密钥或初始化向量时，可以使用该方法。会修改_key、_iv。
 *
 *  @param data      明文/密文
 *  @param key       密钥
 *  @param iv        初始化向量，可以为空
 *  @param operation kCCEncrypt/kCCDecrypt
 *
 *  @return 加密/解密后的数据
 */
- (NSData * _Nullable)doCipher:(NSData * _Nonnull)data
                           key:(NSData * _Nonnull)key
                            iv:(NSData * _Nullable)iv
                     operation:(CCOperation)operation;
@end
