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
 *  加解密操作，不要修改对应的值
 */
typedef NS_ENUM(CCOperation, INBRSAOperation){
	/**
	 *  加密操作
	 */
	INBRSAOperationEncrypt = kCCEncrypt,
	/**
	 *  解密操作
	 */
	INBRSAOperationDecrypt = kCCDecrypt,
};

/**
 *  密钥长度，不要修改对应的值
 */
typedef NS_ENUM(NSUInteger, INBRSAKeySizeInBits){
	/**
	 *  2048位
	 */
	INBRSAKeySizeInBits2048 = 1 << 11,
	/**
	 *  1024位
	 */
	INBRSAKeySizeInBits1024 = 1 << 10,
};

/**
 *  RSA，加解密时使用kSecPaddingPKCS1，默认生成的密钥的长度为2048位
 */
@interface INBRSA : NSObject
@property (nonatomic, readonly) SecKeyRef privateKey;
@property (nonatomic, readonly) SecKeyRef publicKey;
/**
 *  创建及验证数字签名时，所使用的填充模式，必须是kSecPaddingPKCS1SHA*，默认为kSecPaddingPKCS1SHA1
 */
@property (nonatomic) SecPadding padding;
+ (instancetype)sharedINBRSA;
/**
 *  生成公私钥对。密钥长度为2048位。
 *
 *  @return 是否成功生成公私钥对，成功：YES，失败：NO
 */
- (BOOL)generateKeys;
/**
 *  根据指定的密钥长度，生成公私钥对。当前只支持INBRSAKeySizeInBits中声明的长度。
 *
 *  @return 是否成功生成公私钥对，成功：YES，失败：NO
 */
- (BOOL)generateKeys:(INBRSAKeySizeInBits)keySizeInBits;
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
- (BOOL)publicKeyFromDERData:(NSData *)data;
/**
 *  从个人信息交换文件中获取公钥及私钥
 *
 *  @param filePath 个人信息交换文件路径
 *  @param password 文件密码
 *
 *  @return 是否成功提取到公钥及私钥，成功：YES，失败：NO
 */
- (BOOL)keysFromPersonalInformationExchangeFile:(NSString *)filePath
									   password:(NSString *)pwd;
/**
 *  从数据中获取公钥及私钥
 *
 *  @param data     数据
 *  @param password 文件密码
 *
 *  @return 是否成功提取到公钥及私钥，成功：YES，失败：NO
 */
- (BOOL)keysFromData:(NSData *)data
			password:(NSString *)pwd;
/**
 *  使用公钥对数据进行加密
 *
 *  @param data 数据
 *
 *  @return 加密后的数据
 */
- (NSData *)encryptDataWithPublicKey:(NSData *)data;
/**
 *  使用私钥对数据进行解密
 *
 *  @param data 数据
 *
 *  @return 解密后的数据
 */
- (NSData *)decryptDataWithPrivateKey:(NSData *)data;
/**
 *  对数据进行签名。先获取data的摘要信息，再对摘要进行签名。
 *
 *  @param data 数据
 *
 *  @return 数字签名
 */
- (NSData *)signDataWithPrivateKey:(NSData *)data;
/**
 *  对数字签名进行验签。先获取data的摘要信息，再进行验签。
 *
 *  @param data             数据
 *  @param digitalSignature 数字签名
 *
 *  @return 验签是否成功
 */
- (BOOL)verifyDataWithPublicKey:(NSData *)data digitalSignature:(NSData *)digitalSignature;
@end
