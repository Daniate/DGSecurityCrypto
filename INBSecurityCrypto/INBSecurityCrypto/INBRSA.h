//
//  INBRSA.h
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

/**
 *  密钥长度，以比特为单位
 */
FOUNDATION_EXPORT NSUInteger const INBRSAKeySizeInBits2048;
FOUNDATION_EXPORT NSUInteger const INBRSAKeySizeInBits1024;

/**
 *  RSA，加解密时使用kSecPaddingPKCS1，默认生成的密钥的长度为2048位
 */
@interface INBRSA : NSObject
@property (nonatomic, readonly, nullable) SecKeyRef privateKey;
@property (nonatomic, readonly, nullable) SecKeyRef publicKey;
/**
 *  创建及验证数字签名时，所使用的填充模式，必须是kSecPaddingPKCS1SHA*，默认为kSecPaddingPKCS1SHA1
 */
@property (nonatomic) SecPadding padding;
+ (nonnull instancetype)sharedINBRSA;
/**
 *  生成公私钥对。密钥长度为2048位。
 *
 *  @return 是否成功生成公私钥对，成功：YES，失败：NO
 */
- (BOOL)generateKeys;
/**
 根据指定的密钥长度，生成公私钥对。当前只支持INBRSAKeySizeInBits中声明的长度。

 @param keySizeInBits INBRSAKeySizeInBits2048 / INBRSAKeySizeInBits1024
 @return 是否成功生成公私钥对，成功：YES，失败：NO
 */
- (BOOL)generateKeys:(NSUInteger)keySizeInBits;
/**
 *  从X.509证书数据中获取公钥
 *
 *  <ol>
 *  <li>从文件中获取公钥：<br/>[rsa publicKeyFromDERData:[NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"a" ofType:@"cer"]]];</li>
 *  <li>从字符串中获取公钥：<br/>[rsa publicKeyFromDERData:[NSData base64DecodedDataWithString:kPublicKeyBase64]];<br/><br/><b>注：</b>kPublicKeyBase64是"-----BEGIN CERTIFICATE-----"与"-----END CERTIFICATE-----"之间的Base64字符串，以文本形式打开pem文件可以看到该字符串</li>
 *  </ol>
 *  
 *  证书格式转换命令：<br/>`openssl x509 -in a.cer -inform DER -out b.pem -outform PEM`
 *
 *  @param data DER编码格式的X.509证书数据
 *
 *  @return 是否成功提取到公钥，成功：YES，失败：NO
 */
- (BOOL)publicKeyFromDERData:(NSData * _Nonnull)data;
/**
 *  从个人信息交换文件中获取公钥及私钥
 *
 *  @param filePath 个人信息交换文件路径
 *  @param pwd 文件密码
 *
 *  @return 是否成功提取到公钥及私钥，成功：YES，失败：NO
 */
- (BOOL)keysFromPersonalInformationExchangeFile:(NSString * _Nonnull)filePath password:(NSString * _Nullable)pwd;
/**
 *  从数据中获取公钥及私钥
 *
 *  @param data     数据
 *  @param pwd 文件密码
 *
 *  @return 是否成功提取到公钥及私钥，成功：YES，失败：NO
 */
- (BOOL)keysFromData:(NSData * _Nonnull)data password:(NSString * _Nullable)pwd;
/**
 *  使用公钥对数据进行加密
 *
 *  @param data 数据
 *
 *  @return 加密后的数据
 */
- (NSData * _Nullable)encryptDataWithPublicKey:(NSData * _Nonnull)data;
/**
 *  使用私钥对数据进行解密
 *
 *  @param data 数据
 *
 *  @return 解密后的数据
 */
- (NSData * _Nullable)decryptDataWithPrivateKey:(NSData * _Nonnull)data;
/**
 *  对数据进行签名。先获取data的摘要信息，再对摘要进行签名。
 *
 *  @param data 数据
 *
 *  @return 数字签名
 */
- (NSData * _Nullable)signDataWithPrivateKey:(NSData * _Nonnull)data;
/**
 *  对数字签名进行验签。先获取data的摘要信息，再进行验签。
 *
 *  @param data             数据
 *  @param digitalSignature 数字签名
 *
 *  @return 验签是否成功
 */
- (BOOL)verifyDataWithPublicKey:(NSData * _Nonnull)data digitalSignature:(NSData * _Nonnull)digitalSignature;
@end
