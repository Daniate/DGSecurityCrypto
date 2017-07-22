//
//  INBRSA.m
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import "INBRSA.h"
#import "NSData+INB.h"

NSUInteger const INBRSAKeySizeInBits2048 = 1 << 11;
NSUInteger const INBRSAKeySizeInBits1024 = 1 << 10;

@interface INBRSA () {
	SecKeyRef _privateKey;
	SecKeyRef _publicKey;
}

@end

@implementation INBRSA
static INBRSA *sharedINBRSA = nil;
+ (nonnull instancetype)sharedINBRSA {
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

- (BOOL)generateKeys:(NSUInteger)keySizeInBits {
	NSParameterAssert(keySizeInBits == INBRSAKeySizeInBits2048 || keySizeInBits == INBRSAKeySizeInBits1024);
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

- (BOOL)keysFromPersonalInformationExchangeFile:(NSString * _Nonnull)filePath password:(NSString * _Nullable)pwd {
    if (filePath == nil) {
        return NO;
    }
	return [self keysFromData:[NSData dataWithContentsOfFile:filePath] password:pwd];
}

- (void)_freeDictionary:(CFDictionaryRef * _Nullable)dictionary array:(CFArrayRef * _Nullable)array {
    if (dictionary && *dictionary) {
        CFRelease(*dictionary);
        *dictionary = NULL;
    }
    if (array && *array) {
        CFRelease(*array);
        *array = NULL;
    }
}

- (BOOL)keysFromData:(NSData * _Nonnull)data password:(NSString * _Nullable)pwd {
    if (data == nil) {
        return NO;
    }
	// 清理之前所生成的密钥，避免当无法获取密钥时，_publicKey、_privateKey依旧有值
	_publicKey = NULL;
	_privateKey = NULL;
    CFDictionaryRef options = NULL;
    if (pwd) {
        const void *keys[] = {
            kSecImportExportPassphrase,
        };
        const void *values[] = {
            (__bridge CFStringRef)pwd,
        };
        options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, NULL, NULL);
    } else {
        options = CFDictionaryCreate(kCFAllocatorDefault, NULL, NULL, 0, NULL, NULL);
    }
    if (options == NULL) {
        return NO;
    }
	CFArrayRef items = CFArrayCreate(kCFAllocatorDefault, NULL, 0, NULL);
    if (items == NULL) {
        [self _freeDictionary:&options array:NULL];
        return NO;
    }
	OSStatus status = SecPKCS12Import((__bridge CFDataRef)data, options, &items);
    if (status != errSecSuccess) {
        [self _freeDictionary:&options array:&items];
        return NO;
    }
    CFDictionaryRef identity_trust_dic = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemIdentity);
    if (identity == NULL) {
        [self _freeDictionary:&options array:&items];
        return NO;
    }
    SecTrustRef trust = (SecTrustRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemTrust);
    if (trust == NULL) {
        [self _freeDictionary:&options array:&items];
        return NO;
    }
    // certs数组中包含了所有的证书
    CFArrayRef certs = (CFArrayRef)CFDictionaryGetValue(identity_trust_dic, kSecImportItemCertChain);
    if ([(__bridge NSArray *)certs count] == 0) {
        [self _freeDictionary:&options array:&items];
        return NO;
    }
    // 如果没有下面一句，自签名证书的评估信任结果永远是kSecTrustResultRecoverableTrustFailure
    status = SecTrustSetAnchorCertificates(trust, certs);
    if (status != errSecSuccess) {
        [self _freeDictionary:&options array:&items];
        return NO;
    }
    SecTrustResultType trustResultType;
    // 通常, 返回的trust result type应为kSecTrustResultUnspecified，如果是，就可以说明签名证书是可信的
    status = SecTrustEvaluate(trust, &trustResultType);
    if (status != errSecSuccess) {
        [self _freeDictionary:&options array:&items];
        return NO;
    }
    if (trustResultType == kSecTrustResultUnspecified ||
        trustResultType == kSecTrustResultProceed) {
        // 证书可信，可以提取私钥与公钥，然后可以使用公私钥进行加解密操作
        status = SecIdentityCopyPrivateKey(identity, &_privateKey);
        _publicKey = SecTrustCopyPublicKey(trust);
    }
	[self _freeDictionary:&options array:&items];
	return (status == errSecSuccess && _privateKey && _publicKey);
}

- (void)_freeCertificate:(SecCertificateRef * _Nullable)cert
                  policy:(SecPolicyRef * _Nullable)policy
                   trust:(SecTrustRef * _Nullable)trust {
    if (trust && *trust) {
        CFRelease(*trust);
        *trust = NULL;
    }
    if (policy && *policy) {
        CFRelease(*policy);
        *policy = NULL;
    }
    if (cert && *cert) {
        CFRelease(*cert);
        *cert = NULL;
    }
}

- (BOOL)publicKeyFromDERData:(NSData * _Nonnull)data {
    if (data == nil) {
        return NO;
    }
    SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)data);
    if (cert == NULL) {
        return NO;
    }
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    if (policy == NULL) {
        [self _freeCertificate:&cert policy:NULL trust:NULL];
        return NO;
    }
    SecTrustRef trust = NULL;
    OSStatus status = SecTrustCreateWithCertificates(cert, policy, &trust);
    if (trust == NULL) {
        [self _freeCertificate:&cert policy:&policy trust:NULL];
        return NO;
    }
    if (status != errSecSuccess) {
        [self _freeCertificate:&cert policy:&policy trust:&trust];
        return NO;
    }
    NSArray *certs = [NSArray arrayWithObject:(__bridge id)cert];
    status = SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)certs);
    if (status != errSecSuccess) {
        [self _freeCertificate:&cert policy:&policy trust:&trust];
        return NO;
    }
    SecTrustResultType trustResult = kSecTrustResultInvalid;
    status = SecTrustEvaluate(trust, &trustResult);
    if (status != errSecSuccess) {
        [self _freeCertificate:&cert policy:&policy trust:&trust];
        return NO;
    }
    // 自签名证书可信
    if (trustResult == kSecTrustResultUnspecified ||
        trustResult == kSecTrustResultProceed) {
        // 重新获取公钥后，原有的私钥_privateKey可能就与新的公钥不匹配了
        _publicKey = SecTrustCopyPublicKey(trust);
    }
    [self _freeCertificate:&cert policy:&policy trust:&trust];
    return YES;
}

- (NSData * _Nullable)encryptDataWithPublicKey:(NSData * _Nonnull)data {
	return [self doCipherWithData:data
							  key:self.publicKey
						operation:kCCEncrypt];
}

- (NSData * _Nullable)decryptDataWithPrivateKey:(NSData * _Nonnull)data {
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

- (NSData * _Nullable)doCipherWithData:(NSData * _Nonnull)data
						 key:(SecKeyRef)key
				   operation:(CCOperation)operation {
	if (data.length == 0 ||
		key == NULL ||
		(operation != kCCEncrypt &&
		 operation != kCCDecrypt)) {
			return nil;
		}
	// 分配内存块，用于存放加密/解密后的数据段
	size_t bufSize = SecKeyGetBlockSize(key);
	uint8_t *buf = malloc(bufSize * sizeof(uint8_t));
    if (buf == NULL) {
        NSLog(@"%s (Cannot alloc memory.)", __PRETTY_FUNCTION__);
        return nil;
    }
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
    BOOL interrupt = NO;
	// 分段加密/解密
	for (int i = 0; i < blockCount; i++) {
		NSUInteger loc = i * blockSize;
		// 数据段的实际大小。最后一段可能比blockSize小。
		NSUInteger dataSegmentRealSize = MIN(blockSize, totalLength - loc);
		// 截取需要加密/解密的数据段
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
            interrupt = YES;
            break;
		}
	}
	if (buf) {
		free(buf);
		buf = NULL;
	}
	return interrupt ? nil : outData;
}

- (NSData * _Nullable)signDataWithPrivateKey:(NSData * _Nonnull)data {
	// 消息摘要
	NSData *digest = nil;
	switch (self.padding) {
		// 自iOS 5.0起，不再支持kSecPaddingPKCS1MD2、kSecPaddingPKCS1MD5
//		case kSecPaddingPKCS1MD2:/* Unsupported as of iOS 5.0 */
//		{
//			digest = [data dg_MD2];
//			break;
//		}
//		case kSecPaddingPKCS1MD5:/* Unsupported as of iOS 5.0 */
//		{
//			digest = [data dg_MD5];
//			break;
//		}
		case kSecPaddingPKCS1SHA1:
		{
			digest = [data dg_SHA1];
			break;
		}
		case kSecPaddingPKCS1SHA224:
		{
			digest = [data dg_SHA224];
			break;
		}
		case kSecPaddingPKCS1SHA256:
		{
			digest = [data dg_SHA256];
			break;
		}
		case kSecPaddingPKCS1SHA384:
		{
			digest = [data dg_SHA384];
			break;
		}
		case kSecPaddingPKCS1SHA512:
		{
			digest = [data dg_SHA512];
			break;
		}
		default:
        {
            NSLog(@"%s (Unsupported padding mode.)", __PRETTY_FUNCTION__);
            return nil;
        }
	}
	// 分配内存块，用于存放签名后的数据
	size_t sigLen = SecKeyGetBlockSize(self.privateKey);
	uint8_t *sig = malloc(sigLen * sizeof(uint8_t));
    if (sig == NULL) {
        NSLog(@"%s (Cannot alloc memory.)", __PRETTY_FUNCTION__);
        return nil;
    }
	NSData *outData = nil;
    memset(sig, '\0', sigLen);
    const uint8_t *dataToSign = digest.bytes;
    size_t dataToSignLen = digest.length;
    // 对消息摘要进行签名
    OSStatus status = SecKeyRawSign(self.privateKey, self.padding, dataToSign, dataToSignLen, sig, &sigLen);
    if (status == errSecSuccess) {
        outData = [NSData dataWithBytes:(const void *)sig
                                 length:sigLen];
    }
    free(sig);
    sig = NULL;
	return outData;
}

- (BOOL)verifyDataWithPublicKey:(NSData * _Nonnull)data digitalSignature:(NSData * _Nonnull)digitalSignature {
	// 消息摘要
	NSData *digest = nil;
	switch (self.padding) {
		// 自iOS 5.0起，不再支持kSecPaddingPKCS1MD2、kSecPaddingPKCS1MD5
//		case kSecPaddingPKCS1MD2:
//		{
//			digest = [data dg_MD2];/* Unsupported as of iOS 5.0 */
//			break;
//		}
//		case kSecPaddingPKCS1MD5:
//		{
//			digest = [data dg_MD5];/* Unsupported as of iOS 5.0 */
//			break;
//		}
		case kSecPaddingPKCS1SHA1:
		{
			digest = [data dg_SHA1];
			break;
		}
		case kSecPaddingPKCS1SHA224:
		{
			digest = [data dg_SHA224];
			break;
		}
		case kSecPaddingPKCS1SHA256:
		{
			digest = [data dg_SHA256];
			break;
		}
		case kSecPaddingPKCS1SHA384:
		{
			digest = [data dg_SHA384];
			break;
		}
		case kSecPaddingPKCS1SHA512:
		{
			digest = [data dg_SHA512];
			break;
		}
		default:
        {
            NSLog(@"%s (Unsupported padding mode.)", __PRETTY_FUNCTION__);
            return NO;
        }
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
