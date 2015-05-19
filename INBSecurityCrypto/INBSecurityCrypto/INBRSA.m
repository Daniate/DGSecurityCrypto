//
//  INBRSA.m
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import "INBRSA.h"
#import "NSData+INB.h"

@interface INBRSA () {
	SecKeyRef _privateKey;
	SecKeyRef _publicKey;
}

@end

@implementation INBRSA
static INBRSA *sharedINBRSA = nil;
+ (instancetype)sharedINBRSA {
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		sharedINBRSA = [[super allocWithZone:NULL] init];
		sharedINBRSA.padding = kSecPaddingPKCS1SHA1;
		[sharedINBRSA generateKeys];
	});
	return sharedINBRSA;
}
+ (id)allocWithZone:(struct _NSZone *)zone {
	return [INBRSA sharedINBRSA];
}

- (void)setPadding:(SecPadding)padding {
	// kSecPaddingPKCS1MD2 and kSecPaddingPKCS1MD5, Unsupported as of iOS 5.0
	// 自iOS 5.0起，不再支持kSecPaddingPKCS1MD2、kSecPaddingPKCS1MD5
	NSParameterAssert(/*padding == kSecPaddingPKCS1MD2 ||
					  padding == kSecPaddingPKCS1MD5 ||*/
					  padding == kSecPaddingPKCS1SHA1 ||
					  padding == kSecPaddingPKCS1SHA224 ||
					  padding == kSecPaddingPKCS1SHA256 ||
					  padding == kSecPaddingPKCS1SHA384 ||
					  padding == kSecPaddingPKCS1SHA512);
	_padding = padding;
}

- (BOOL)generateKeys {
	return [self generateKeys:INBRSAKeySizeInBits2048];
}

- (BOOL)generateKeys:(INBRSAKeySizeInBits)keySizeInBits {
	NSParameterAssert(keySizeInBits == 1 << 11 || keySizeInBits == 1 << 10);
	// 即便设置了公钥解密、私钥加密，但测试的结果是返回-4（errSecUnimplemented），推测：iOS未实现公钥解密、私钥加密
//	NSDictionary *privateKeyAttrs = @{
//									  (__bridge __strong id)kSecAttrCanEncrypt: (__bridge __strong id)kCFBooleanTrue,
//									  (__bridge __strong id)kSecAttrCanDecrypt: (__bridge __strong id)kCFBooleanTrue,
//									  (__bridge __strong id)kSecAttrCanSign: (__bridge __strong id)kCFBooleanTrue,
//									  };
//	NSDictionary *publicKeyAttrs = @{
//									 (__bridge __strong id)kSecAttrCanEncrypt: (__bridge __strong id)kCFBooleanTrue,
//									 (__bridge __strong id)kSecAttrCanDecrypt: (__bridge __strong id)kCFBooleanTrue,
//									 (__bridge __strong id)kSecAttrCanVerify: (__bridge __strong id)kCFBooleanTrue,
//									 };
	NSDictionary *parameters = @{
								 (__bridge __strong id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
								 (__bridge __strong id)kSecAttrKeySizeInBits: @(keySizeInBits),
//								 (__bridge __strong id)kSecPrivateKeyAttrs: privateKeyAttrs,
//								 (__bridge __strong id)kSecPublicKeyAttrs: publicKeyAttrs,
								 };
	OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)(parameters), &_publicKey, &_privateKey);
	return (status == errSecSuccess);
}

- (BOOL)keysFromPersonalInformationExchangeFile:(NSString *)filePath password:(NSString *)pwd {
	return [self keysFromData:[NSData dataWithContentsOfFile:filePath] password:pwd];
}

- (BOOL)keysFromData:(NSData *)data password:(NSString *)pwd {
	// 清理之前所生成的密钥，避免当无法获取密钥时，_publicKey、_privateKey依旧有值
	_publicKey = NULL;
	_privateKey = NULL;
	const void *keys[] = {
		kSecImportExportPassphrase,
	};
	const void *values[] = {
		(__bridge CFStringRef)pwd,
	};
	CFDictionaryRef options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, NULL, NULL);
	CFArrayRef items = CFArrayCreate(kCFAllocatorDefault, NULL, 0, NULL);
	OSStatus status = SecPKCS12Import((__bridge CFDataRef)data, options, &items);
	if (status == errSecSuccess) {
		CFDictionaryRef identity_trust_dic = CFArrayGetValueAtIndex(items, 0);
		SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemIdentity);
		SecTrustRef trust = (SecTrustRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemTrust);
		// certs数组中包含了所有的证书
		CFArrayRef certs = (CFArrayRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemCertChain);
		if ([(__bridge NSArray *)certs count] && trust && identity) {
			// 如果没有下面一句，自签名证书的评估信任结果永远是kSecTrustResultRecoverableTrustFailure
			status = SecTrustSetAnchorCertificates(trust, certs);
			if (status == errSecSuccess) {
				SecTrustResultType trustResultType;
				// 通常, 返回的trust result type应为kSecTrustResultUnspecified，如果是，就可以说明签名证书是可信的
				status = SecTrustEvaluate(trust, &trustResultType);
				if ((trustResultType == kSecTrustResultUnspecified || trustResultType == kSecTrustResultProceed) && status == errSecSuccess) {
					// 证书可信，可以提取私钥与公钥，然后可以使用公私钥进行加解密操作
					status = SecIdentityCopyPrivateKey(identity, &_privateKey);
					_publicKey = SecTrustCopyPublicKey(trust);
				} else {
					status = -1;
				}
			} else {
				status = -1;
			}
		} else {
			status = -1;
		}
	}
	if (options) {
		CFRelease(options);
		options = NULL;
	}
	if (items) {
		CFRelease(items);
		items = NULL;
	}
	return (status == errSecSuccess);
}

- (BOOL)publicKeyFromDERData:(NSData *)data {
	// 清理之前所生成的公钥。注意，重新获取公钥后，原有的私钥_privateKey可能就与新的公钥不匹配了
	_publicKey = NULL;
	SecTrustRef trust = NULL;
	SecTrustResultType trustResult = kSecTrustResultInvalid;
	SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)data);
	SecPolicyRef policy = SecPolicyCreateBasicX509();
	OSStatus status = SecTrustCreateWithCertificates(cert, policy, &trust);
	if (status == errSecSuccess && trust) {
		NSArray *certs = [NSArray arrayWithObject:(__bridge id)cert];
		status = SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)certs);
		if (status == errSecSuccess) {
			status = SecTrustEvaluate(trust, &trustResult);
			// 自签名证书可信
			if (status == errSecSuccess &&
				(trustResult == kSecTrustResultUnspecified ||
				 trustResult == kSecTrustResultProceed)) {
				_publicKey = SecTrustCopyPublicKey(trust);
			}
		}
	}
	if (trust) {
		CFRelease(trust);
		trust = NULL;
	}
	if (policy) {
		CFRelease(policy);
		policy = NULL;
	}
	if (cert) {
		CFRelease(cert);
		cert = NULL;
	}
	return (status == errSecSuccess && _publicKey != NULL);
}

- (NSData *)encryptDataWithPublicKey:(NSData *)data {
	return [self doCipherWithData:data
							  key:self.publicKey
						operation:kCCEncrypt];
}

- (NSData *)decryptDataWithPrivateKey:(NSData *)data {
	return [self doCipherWithData:data
							  key:self.privateKey
						operation:kCCDecrypt];
}

//- (NSData *)encryptDataWithPrivateKey:(NSData *)data {
//	return [self doCipherWithData:data
//							  key:self.privateKey
//						operation:kCCEncrypt];
//}

//- (NSData *)decryptDataWithPublicKey:(NSData *)data {
//	return [self doCipherWithData:data
//							  key:self.publicKey
//						operation:kCCDecrypt];
//}

- (NSData *)doCipherWithData:(NSData *)data
						 key:(SecKeyRef)key
				   operation:(INBRSAOperation)operation {
	if (data.length == 0 ||
		key == NULL ||
		(operation != kCCEncrypt &&
		 operation != kCCDecrypt) ) {
		return nil;
	}
	// 分配内存块，用于存放解密后的数据段
	size_t bufSize = SecKeyGetBlockSize(key);
	uint8_t *buf = malloc(bufSize * sizeof(uint8_t));
	// 计算数据段最大长度及数据段的个数
	double totalLength = data.length;
	size_t blockSize = bufSize;
	/**
	 * When PKCS1 padding is performed, the maximum length of data 
	 * that can be encrypted is 11 bytes less than the value 
	 * returned by the SecKeyGetBlockSize function
	 */
	if (operation == kCCEncrypt) {
		blockSize -= 11;
	}
	size_t blockCount = (size_t)ceil(totalLength / blockSize);
	NSMutableData *outData = [NSMutableData data];
	// 分段解密
	for (int i = 0; i < blockCount; i++) {
		NSUInteger loc = i * blockSize;
		// 数据段的实际大小。最后一段可能比blockSize小。
		NSUInteger dataSegmentRealSize = MIN(blockSize, totalLength - loc);
		// 截取需要解密的数据段
		NSData *dataSegment = [data subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
		OSStatus status = -1;
		if (operation == kCCEncrypt) {
			status = SecKeyEncrypt(key,
								   kSecPaddingPKCS1,
								   (const uint8_t *)[dataSegment bytes],
								   dataSegmentRealSize,
								   buf,
								   &bufSize);
		} else if (operation == kCCDecrypt) {
			status = SecKeyDecrypt(key,
								   kSecPaddingPKCS1,
								   (const uint8_t *)[dataSegment bytes],
								   dataSegmentRealSize,
								   buf,
								   &bufSize);
		}
		if (status == errSecSuccess) {
			[outData appendData:[NSData dataWithBytes:(const void *)buf
											   length:bufSize]];
		} else {
			if (buf) {
				free(buf);
				buf = NULL;
			}
			return nil;
		}
	}
	if (buf) {
		free(buf);
		buf = NULL;
	}
	return outData;
}

- (NSData *)signDataWithPrivateKey:(NSData *)data {
	// 消息摘要
	NSData *digest = nil;
	switch (self.padding) {
		// 自iOS 5.0起，不再支持kSecPaddingPKCS1MD2、kSecPaddingPKCS1MD5
//		case kSecPaddingPKCS1MD2:/* Unsupported as of iOS 5.0 */
//		{
//			digest = [data MD2];
//			break;
//		}
//		case kSecPaddingPKCS1MD5:/* Unsupported as of iOS 5.0 */
//		{
//			digest = [data MD5];
//			break;
//		}
		case kSecPaddingPKCS1SHA1:
		{
			digest = [data SHA1];
			break;
		}
		case kSecPaddingPKCS1SHA224:
		{
			digest = [data SHA224];
			break;
		}
		case kSecPaddingPKCS1SHA256:
		{
			digest = [data SHA256];
			break;
		}
		case kSecPaddingPKCS1SHA384:
		{
			digest = [data SHA384];
			break;
		}
		case kSecPaddingPKCS1SHA512:
		{
			digest = [data SHA512];
			break;
		}
		default:
			break;
	}
	const uint8_t *dataToSign = digest.bytes;
	size_t dataToSignLen = digest.length;
	// 分配内存块，用于存放签名后的数据
	size_t sigLen = SecKeyGetBlockSize(self.privateKey);
	uint8_t *sig = malloc(sigLen * sizeof(uint8_t));
	memset(sig, 0x0, sigLen);
	// 对消息摘要进行签名
	OSStatus status = SecKeyRawSign(self.privateKey, self.padding, dataToSign, dataToSignLen, sig, &sigLen);
	NSMutableData *outData = [NSMutableData data];
	if (status == errSecSuccess) {
		[outData appendData:[NSData dataWithBytes:(const void *)sig
										   length:sigLen]];
	} else {
		if (sig) {
			free(sig);
			sig = NULL;
		}
		return nil;
	}
	if (sig) {
		free(sig);
		sig = NULL;
	}
	return outData;
}

- (BOOL)verifyDataWithPublicKey:(NSData *)data digitalSignature:(NSData *)digitalSignature {
	// 消息摘要
	NSData *digest = nil;
	switch (self.padding) {
		// 自iOS 5.0起，不再支持kSecPaddingPKCS1MD2、kSecPaddingPKCS1MD5
//		case kSecPaddingPKCS1MD2:
//		{
//			digest = [data MD2];/* Unsupported as of iOS 5.0 */
//			break;
//		}
//		case kSecPaddingPKCS1MD5:
//		{
//			digest = [data MD5];/* Unsupported as of iOS 5.0 */
//			break;
//		}
		case kSecPaddingPKCS1SHA1:
		{
			digest = [data SHA1];
			break;
		}
		case kSecPaddingPKCS1SHA224:
		{
			digest = [data SHA224];
			break;
		}
		case kSecPaddingPKCS1SHA256:
		{
			digest = [data SHA256];
			break;
		}
		case kSecPaddingPKCS1SHA384:
		{
			digest = [data SHA384];
			break;
		}
		case kSecPaddingPKCS1SHA512:
		{
			digest = [data SHA512];
			break;
		}
		default:
			break;
	}
	const uint8_t *signedData = digest.bytes;
	size_t signedDataLen = digest.length;
	// 数字签名
	const uint8_t *sig = digitalSignature.bytes;
	size_t sigLen = digitalSignature.length;
	// 验签
	OSStatus status = SecKeyRawVerify(self.publicKey, self.padding, signedData, signedDataLen, sig, sigLen);
	return (status == errSecSuccess);
}
@end
