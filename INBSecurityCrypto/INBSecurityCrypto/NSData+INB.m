//
//  NSData+INB.m
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import "NSData+INB.h"
#import "INBMacroAdditions.h"
#ifdef __IPHONE_8_0
#import <CommonCrypto/CommonRandom.h>
#endif

@implementation NSData (INBBase64)
- (NSString *)base64EncodedString {
#ifdef __IPHONE_7_0
	if (INBIOS7_0_0OrLater) {
		NSDataBase64EncodingOptions options = NSDataBase64Encoding64CharacterLineLength|NSDataBase64EncodingEndLineWithCarriageReturn|NSDataBase64EncodingEndLineWithLineFeed;
		return [self base64EncodedStringWithOptions:options];
	} else {
#endif
		return [self base64Encoding];
#ifdef __IPHONE_7_0
	}
#endif
}
- (NSData *)base64EncodedData {
#ifdef __IPHONE_7_0
	if (INBIOS7_0_0OrLater) {
		NSDataBase64EncodingOptions options = NSDataBase64Encoding64CharacterLineLength|NSDataBase64EncodingEndLineWithCarriageReturn|NSDataBase64EncodingEndLineWithLineFeed;
		return [self base64EncodedDataWithOptions:options];
	} else {
#endif
		return [[self base64Encoding] dataUsingEncoding:NSUTF8StringEncoding];
#ifdef __IPHONE_7_0
	}
#endif
}
+ (NSData *)base64DecodedDataWithString:(NSString *)base64String {
#ifdef __IPHONE_7_0
	if (INBIOS7_0_0OrLater) {
		return [[NSData alloc] initWithBase64EncodedString:base64String
												   options:NSDataBase64DecodingIgnoreUnknownCharacters];
	} else {
#endif
		return [[NSData alloc] initWithBase64Encoding:base64String];
#ifdef __IPHONE_7_0
	}
#endif
}
+ (NSData *)base64DecodedDataWithData:(NSData *)base64Data {
#ifdef __IPHONE_7_0
	if (INBIOS7_0_0OrLater) {
		return [[NSData alloc] initWithBase64EncodedData:base64Data
												 options:NSDataBase64DecodingIgnoreUnknownCharacters];
	} else {
#endif
		NSString *base64String = [[NSString alloc] initWithData:base64Data encoding:NSUTF8StringEncoding];
		return [[NSData alloc] initWithBase64Encoding:base64String];
#ifdef __IPHONE_7_0
	}
#endif
}
- (NSData *)base64DecodedData {
	return [NSData base64DecodedDataWithData:self];
}
@end

@implementation NSData (INBMessageDigest)
- (NSData *)MD2 {
	unsigned char md[CC_MD2_DIGEST_LENGTH] = {0};
	CC_MD2(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_MD2_DIGEST_LENGTH];
}
- (NSData *)MD4 {
	unsigned char md[CC_MD4_DIGEST_LENGTH] = {0};
	CC_MD4(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_MD4_DIGEST_LENGTH];
}
- (NSData *)MD5 {
	unsigned char md[CC_MD5_DIGEST_LENGTH] = {0};
	CC_MD5(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_MD5_DIGEST_LENGTH];
}
- (NSData *)SHA1 {
	unsigned char md[CC_SHA1_DIGEST_LENGTH] = {0};
	CC_SHA1(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA1_DIGEST_LENGTH];
}
- (NSData *)SHA224 {
	unsigned char md[CC_SHA224_DIGEST_LENGTH] = {0};
	CC_SHA224(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA224_DIGEST_LENGTH];
}
- (NSData *)SHA256 {
	unsigned char md[CC_SHA256_DIGEST_LENGTH] = {0};
	CC_SHA256(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA256_DIGEST_LENGTH];
}
- (NSData *)SHA384 {
	unsigned char md[CC_SHA384_DIGEST_LENGTH] = {0};
	CC_SHA384(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA384_DIGEST_LENGTH];
}
- (NSData *)SHA512 {
	unsigned char md[CC_SHA512_DIGEST_LENGTH] = {0};
	CC_SHA512(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA512_DIGEST_LENGTH];
}
@end

@implementation NSData (INBHex)
static const unsigned char digits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
//static const unsigned char digits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
- (NSData *)encodeToHexData {
	if (self == nil) {
		return nil;
	}
	NSUInteger len = self.length;
	unsigned char *bytes = (unsigned char *)self.bytes;
	size_t bufSize = (len << 1);
	unsigned char *buf = malloc(bufSize);
	memset(buf, 0x0, len);
	for (NSUInteger i = 0, j = 0; i < len; i++) {
		buf[j] = digits[(0xF0 & bytes[i]) >> 4];
		j++;
		buf[j] = digits[0x0F & bytes[i]];
		j++;
	}
	NSData *encodedData = [NSData dataWithBytes:buf length:bufSize];
	free(buf);
	buf = NULL;
	return encodedData;
}
/**
 *  将十六进制字符转换为十进制数字
 *
 *  @param hex 十六进制字符
 *
 *  @return 十进制数字
 */
static int numberFromHex(unsigned char hex) {
	assert((hex >= '0' && hex <= '9') ||
		   (hex >= 'a' && hex <= 'f') ||
		   (hex >= 'A' && hex <= 'F'));
	if (hex >= '0' && hex <= '9') {
		return hex - '0';
	}
	if (hex >= 'a' && hex <= 'f') {
		return hex - 'a' + 10;
	}
	if (hex >= 'A' && hex <= 'F') {
		return hex - 'A' + 10;
	}
	return 0;
}

- (NSData *)decodeFromHexData {
	if (self == nil) {
		return nil;
	}
	NSUInteger len = self.length;
	NSAssert((len & 0x01) == 0, @"数据长度必须是偶数");
	unsigned char *bytes = (unsigned char *)self.bytes;
	NSUInteger bufSize = (len >> 1) * sizeof(unsigned char);
	unsigned char *buf = malloc(bufSize);
	for (NSUInteger i = 0, j = 0; i < len; j++) {
		unsigned char f = numberFromHex(bytes[i]) << 4;
		i++;
		f = f | numberFromHex(bytes[i]);
		i++;
		buf[j] = f;
	}
	NSData *decodedData = [NSData dataWithBytes:buf length:bufSize];
	free(buf);
	buf = NULL;
	return decodedData;
}

- (NSString *)encodeToHexString {
	return [[NSString alloc] initWithData:[self encodeToHexData]
								 encoding:NSUTF8StringEncoding];
}
@end

@implementation NSData (INBHmac)
+ (NSData *)generateHmacKeyForAlgorithm:(CCHmacAlgorithm)algorithm {
	NSParameterAssert(algorithm == kCCHmacAlgSHA1 ||
					  algorithm == kCCHmacAlgMD5 ||
					  algorithm == kCCHmacAlgSHA256 ||
					  algorithm == kCCHmacAlgSHA384 ||
					  algorithm == kCCHmacAlgSHA512 ||
					  algorithm == kCCHmacAlgSHA224);
	size_t keySize = 0;
	switch (algorithm) {
		case kCCHmacAlgSHA1:
			keySize = CC_SHA1_DIGEST_LENGTH;
			break;
		case kCCHmacAlgMD5:
			keySize = CC_MD5_DIGEST_LENGTH;
			break;
		case kCCHmacAlgSHA256:
			keySize = CC_SHA256_DIGEST_LENGTH;
			break;
		case kCCHmacAlgSHA384:
			keySize = CC_SHA384_DIGEST_LENGTH;
			break;
		case kCCHmacAlgSHA512:
			keySize = CC_SHA512_DIGEST_LENGTH;
			break;
		case kCCHmacAlgSHA224:
			keySize = CC_SHA224_DIGEST_LENGTH;
			break;
		default:
			break;
	}
	void *keyBuf = malloc(keySize);
	memset(keyBuf, 0x0, keySize);
	NSData *key = nil;
	
#ifdef __IPHONE_8_0
	if (INBIOS8_0_0OrLater) {
		CCRNGStatus status = CCRandomGenerateBytes(keyBuf, keySize);
		if (status == kCCSuccess) {
			key = [NSData dataWithBytes:keyBuf length:keySize];
		} else {
			perror(__PRETTY_FUNCTION__);
		}
	} else {
#endif
		if (SecRandomCopyBytes(kSecRandomDefault, keySize, keyBuf) == 0) {
			key = [NSData dataWithBytes:keyBuf length:keySize];
		} else {
			perror(__PRETTY_FUNCTION__);
		}
#ifdef __IPHONE_8_0
	}
#endif
	
	free(keyBuf);
	keyBuf = NULL;
	return key;
}

- (NSData *)HmacWithAlgorithm:(CCHmacAlgorithm)algorithm key:(id)key {
	NSParameterAssert(algorithm == kCCHmacAlgSHA1 ||
					  algorithm == kCCHmacAlgMD5 ||
					  algorithm == kCCHmacAlgSHA256 ||
					  algorithm == kCCHmacAlgSHA384 ||
					  algorithm == kCCHmacAlgSHA512 ||
					  algorithm == kCCHmacAlgSHA224);
	NSParameterAssert(key != nil &&
					  ([key isKindOfClass:[NSData class]] ||
					   [key isKindOfClass:[NSString class]]));
	NSData *keyData = nil;
	if ([key isKindOfClass:[NSString class]]) {
		keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
	} else {
		keyData = (NSData *)key;
	}
	unsigned char buf[CC_SHA512_DIGEST_LENGTH] = {0x0};
	CCHmac(algorithm, keyData.bytes, keyData.length, self.bytes, self.length, buf);
	NSUInteger length = 0;
	switch (algorithm) {
		case kCCHmacAlgSHA1:
			length = CC_SHA1_DIGEST_LENGTH;
			break;
		case kCCHmacAlgMD5:
			length = CC_MD5_DIGEST_LENGTH;
			break;
		case kCCHmacAlgSHA256:
			length = CC_SHA256_DIGEST_LENGTH;
			break;
		case kCCHmacAlgSHA384:
			length = CC_SHA384_DIGEST_LENGTH;
			break;
		case kCCHmacAlgSHA512:
			length = CC_SHA512_DIGEST_LENGTH;
			break;
		case kCCHmacAlgSHA224:
			length = CC_SHA224_DIGEST_LENGTH;
			break;
		default:
			break;
	}
	return [NSData dataWithBytes:buf length:length];
}
@end

@implementation NSData (INBSymmetricKeyGenerator)
+ (NSData *)generateSymmetricKeyForAlgorithm:(CCAlgorithm)algorithm {
	NSParameterAssert(algorithm == kCCAlgorithmAES ||
					  algorithm == kCCAlgorithmDES ||
					  algorithm == kCCAlgorithm3DES ||
					  algorithm == kCCAlgorithmCAST ||
					  algorithm == kCCAlgorithmRC4 ||
					  algorithm == kCCAlgorithmRC2 ||
					  algorithm == kCCAlgorithmBlowfish);
	unsigned int keySize = 0;
	switch (algorithm) {
		case kCCAlgorithmDES:
			keySize = kCCKeySizeDES;
			break;
		case kCCAlgorithm3DES:
			keySize = kCCKeySize3DES;
			break;
		case kCCAlgorithmCAST:
			keySize = kCCKeySizeMaxCAST;
			break;
		case kCCAlgorithmRC4:
			keySize = kCCKeySizeMaxRC4;
			break;
		case kCCAlgorithmRC2:
			keySize = kCCKeySizeMaxRC2;
			break;
		case kCCAlgorithmBlowfish:
			keySize = kCCKeySizeMaxBlowfish;
			break;
		default:// kCCAlgorithmAES
			keySize = kCCKeySizeAES256;
			break;
	}
	void *keyBuf = malloc(keySize);
	memset(keyBuf, 0x0, keySize);
	NSData *key = nil;
	
#ifdef __IPHONE_8_0
	if (INBIOS8_0_0OrLater) {
		CCRNGStatus status = CCRandomGenerateBytes(keyBuf, keySize);
		if (status == kCCSuccess) {
			key = [NSData dataWithBytes:keyBuf length:keySize];
		} else {
			perror(__PRETTY_FUNCTION__);
		}
	} else {
#endif
		if (SecRandomCopyBytes(kSecRandomDefault, keySize, keyBuf) == 0) {
			key = [NSData dataWithBytes:keyBuf length:keySize];
		} else {
			perror(__PRETTY_FUNCTION__);
		}
#ifdef __IPHONE_8_0
	}
#endif
	
	free(keyBuf);
	keyBuf = NULL;
	return key;
}

/*******************************
 enum {
	kCCAlgorithmAES128 = 0,
	kCCAlgorithmAES = 0,
	kCCAlgorithmDES,
	kCCAlgorithm3DES,
	kCCAlgorithmCAST,
	kCCAlgorithmRC4,
	kCCAlgorithmRC2,
	kCCAlgorithmBlowfish
 };
 typedef uint32_t CCAlgorithm;
 
 enum {
	kCCKeySizeAES128          = 16,
	kCCKeySizeAES192          = 24,
	kCCKeySizeAES256          = 32,
	kCCKeySizeDES             = 8,
	kCCKeySize3DES            = 24,
	kCCKeySizeMinCAST         = 5,
	kCCKeySizeMaxCAST         = 16,
	kCCKeySizeMinRC4          = 1,
	kCCKeySizeMaxRC4          = 512,
	kCCKeySizeMinRC2          = 1,
	kCCKeySizeMaxRC2          = 128,
	kCCKeySizeMinBlowfish     = 8,
	kCCKeySizeMaxBlowfish     = 56,
 };
 ******************************/
+ (NSData *)generateSymmetricKeyForAlgorithm:(CCAlgorithm)algorithm
									 keySize:(unsigned int)keySize {
	NSParameterAssert(algorithm == kCCAlgorithmAES ||
					  algorithm == kCCAlgorithmDES ||
					  algorithm == kCCAlgorithm3DES ||
					  algorithm == kCCAlgorithmCAST ||
					  algorithm == kCCAlgorithmRC4 ||
					  algorithm == kCCAlgorithmRC2 ||
					  algorithm == kCCAlgorithmBlowfish);
	switch (algorithm) {
		case kCCAlgorithmDES:
			keySize = kCCKeySizeDES;
			break;
		case kCCAlgorithm3DES:
			keySize = kCCKeySize3DES;
			break;
		case kCCAlgorithmCAST:
			if (keySize < kCCKeySizeMinCAST) {
				keySize = kCCKeySizeMinCAST;
			} else if (keySize > kCCKeySizeMaxCAST) {
				keySize = kCCKeySizeMaxCAST;
			}
			break;
		case kCCAlgorithmRC4:
			if (keySize < kCCKeySizeMinRC4) {
				keySize = kCCKeySizeMinRC4;
			} else if (keySize > kCCKeySizeMaxRC4) {
				keySize = kCCKeySizeMaxRC4;
			}
			break;
		case kCCAlgorithmRC2:
			if (keySize < kCCKeySizeMinRC2) {
				keySize = kCCKeySizeMinRC2;
			} else if (keySize > kCCKeySizeMaxRC2) {
				keySize = kCCKeySizeMaxRC2;
			}
			break;
		case kCCAlgorithmBlowfish:
			if (keySize < kCCKeySizeMinBlowfish) {
				keySize = kCCKeySizeMinBlowfish;
			} else if (keySize > kCCKeySizeMaxBlowfish) {
				keySize = kCCKeySizeMaxBlowfish;
			}
			break;
		default:// kCCAlgorithmAES
			if (keySize <= kCCKeySizeAES128) {
				keySize = kCCKeySizeAES128;
			} else if (keySize <= kCCKeySizeAES192) {
				keySize = kCCKeySizeAES192;
			} else {
				keySize = kCCKeySizeAES256;
			}
			break;
	}
	void *keyBuf = malloc(keySize);
	memset(keyBuf, 0x0, keySize);
	NSData *key = nil;
	
#ifdef __IPHONE_8_0
	if (INBIOS8_0_0OrLater) {
		CCRNGStatus status = CCRandomGenerateBytes(keyBuf, keySize);
		if (status == kCCSuccess) {
			key = [NSData dataWithBytes:keyBuf length:keySize];
		} else {
			perror(__PRETTY_FUNCTION__);
		}
	} else {
#endif
		if (SecRandomCopyBytes(kSecRandomDefault, keySize, keyBuf) == 0) {
			key = [NSData dataWithBytes:keyBuf length:keySize];
		} else {
			perror(__PRETTY_FUNCTION__);
		}
#ifdef __IPHONE_8_0
	}
#endif
	
	free(keyBuf);
	keyBuf = NULL;
	return key;
}
@end

@implementation NSData (INBIVGenerator)
+ (NSData *)generateIVForAlgorithm:(CCAlgorithm)algorithm {
	NSParameterAssert(algorithm == kCCAlgorithmAES ||
					  algorithm == kCCAlgorithmDES ||
					  algorithm == kCCAlgorithm3DES ||
					  algorithm == kCCAlgorithmCAST ||
					  algorithm == kCCAlgorithmRC2 ||
					  algorithm == kCCAlgorithmBlowfish);
	size_t ivSize = 0;
	switch (algorithm) {
		case kCCAlgorithmDES:
			ivSize = kCCBlockSizeDES;
			break;
		case kCCAlgorithm3DES:
			ivSize = kCCBlockSize3DES;
			break;
		case kCCAlgorithmCAST:
			ivSize = kCCBlockSizeCAST;
			break;
		case kCCAlgorithmRC2:
			ivSize = kCCBlockSizeRC2;
			break;
		case kCCAlgorithmBlowfish:
			ivSize = kCCBlockSizeBlowfish;
			break;
		default:// kCCAlgorithmAES
			ivSize = kCCBlockSizeAES128;
			break;
	}
	void *ivBuf = malloc(ivSize);
	memset(ivBuf, 0x0, ivSize);
	NSData *iv = nil;
	
#ifdef __IPHONE_8_0
	if (INBIOS8_0_0OrLater) {
		CCRNGStatus status = CCRandomGenerateBytes(ivBuf, ivSize);
		if (status == kCCSuccess) {
			iv = [NSData dataWithBytes:ivBuf length:ivSize];
		} else {
			perror(__PRETTY_FUNCTION__);
		}
	} else {
#endif
		if (SecRandomCopyBytes(kSecRandomDefault, ivSize, ivBuf) == 0) {
			iv = [NSData dataWithBytes:ivBuf length:ivSize];
		} else {
			perror(__PRETTY_FUNCTION__);
		}
#ifdef __IPHONE_8_0
	}
#endif
	
	free(ivBuf);
	ivBuf = NULL;
	return iv;
}
@end

@implementation NSData (INBSymmetricEncryptionDecryption)

/**
 *  将数据的长度补足为分组大小的整数倍
 *
 *  @param data      数据
 *  @param blockSize 分组大小
 *
 *  @return 补足后的数据
 */
static NSData * padding(NSData *data, size_t blockSize) {
	NSCParameterAssert(blockSize == kCCBlockSizeAES128 ||
					   blockSize == kCCBlockSizeDES ||
					   blockSize == kCCBlockSize3DES ||
					   blockSize == kCCBlockSizeCAST ||
					   blockSize == kCCBlockSizeRC2 ||
					   blockSize == kCCBlockSizeBlowfish);
	NSUInteger tmp = data.length % blockSize;
	if (tmp != 0) {
		NSMutableData *expectedData = [data mutableCopy];
		[expectedData increaseLengthBy:(blockSize - tmp)];
		return [NSData dataWithData:expectedData];
	}
	return data;
}

- (NSData *)doBlockCipherWithAlgorithm:(CCAlgorithm)algorithm
								   key:(NSData *)key
									iv:(NSData *)iv
							 operation:(CCOperation)operation
						isPKCS7Padding:(BOOL)isPKCS7Padding {
	return [self doBlockCipherWithAlgorithm:algorithm
										key:key
										 iv:iv
								  operation:operation
							 isPKCS7Padding:isPKCS7Padding
									  isECB:NO];
}

- (NSData *)doBlockCipherWithAlgorithm:(CCAlgorithm)algorithm
								   key:(NSData *)key
									iv:(NSData *)iv
							 operation:(CCOperation)operation
						isPKCS7Padding:(BOOL)isPKCS7Padding
								 isECB:(BOOL)isECB {
	NSParameterAssert(algorithm == kCCAlgorithmAES ||
					  algorithm == kCCAlgorithmDES ||
					  algorithm == kCCAlgorithm3DES ||
					  algorithm == kCCAlgorithmCAST ||
					  algorithm == kCCAlgorithmRC2 ||
					  algorithm == kCCAlgorithmBlowfish);
	NSParameterAssert(operation == kCCEncrypt ||
					  operation == kCCDecrypt);
	switch (algorithm) {
		case kCCAlgorithmDES:
			NSParameterAssert(key.length == kCCKeySizeDES);
			NSParameterAssert(iv == nil || iv.length == kCCBlockSizeDES);
			break;
		case kCCAlgorithm3DES:
			NSParameterAssert(key.length == kCCKeySize3DES);
			NSParameterAssert(iv == nil || iv.length == kCCBlockSize3DES);
			break;
		case kCCAlgorithmCAST:
			NSParameterAssert(key.length >= kCCKeySizeMinCAST &&
							  key.length <= kCCKeySizeMaxCAST);
			NSParameterAssert(iv == nil || iv.length == kCCBlockSizeCAST);
			break;
		case kCCAlgorithmRC2:
			NSParameterAssert(key.length >= kCCKeySizeMinRC2 &&
							  key.length <= kCCKeySizeMaxRC2);
			NSParameterAssert(iv == nil || iv.length == kCCBlockSizeRC2);
			break;
		case kCCAlgorithmBlowfish:
			NSParameterAssert(key.length >= kCCKeySizeMinBlowfish &&
							  key.length <= kCCKeySizeMaxBlowfish);
			NSParameterAssert(iv == nil || iv.length == kCCBlockSizeBlowfish);
			break;
		default:// kCCAlgorithmAES
			NSParameterAssert(key.length == kCCKeySizeAES128 ||
							  key.length == kCCKeySizeAES192 ||
							  key.length == kCCKeySizeAES256);
			NSParameterAssert(iv == nil || iv.length == kCCBlockSizeAES128);
			break;
	}
	if (self) {
		size_t blockSize = 0;
		switch (algorithm) {
			case kCCAlgorithmDES:
				blockSize = kCCBlockSizeDES;
				break;
			case kCCAlgorithm3DES:
				blockSize = kCCBlockSize3DES;
				break;
			case kCCAlgorithmCAST:
				blockSize = kCCBlockSizeCAST;
				break;
			case kCCAlgorithmRC2:
				blockSize = kCCBlockSizeRC2;
				break;
			case kCCAlgorithmBlowfish:
				blockSize = kCCBlockSizeBlowfish;
				break;
			default:// kCCAlgorithmAES
				blockSize = kCCBlockSizeAES128;
				break;
		}
		NSUInteger len = self.length;
		NSData *inputData = self;
		size_t bufSize = len + blockSize;
		size_t tmp = len % blockSize;
		if (!isPKCS7Padding && tmp != 0) {
			bufSize += (blockSize - tmp);
			inputData = padding(self, blockSize);
		}
		void *buf = malloc(bufSize);
		memset(buf, 0x0, bufSize);
		size_t dataOutMoved = 0;
		
		CCOptions options = 0;
		if (isPKCS7Padding) {
			options |= kCCOptionPKCS7Padding;
		}
		if (isECB) {
			options |= kCCOptionECBMode;
		}
		
		CCCryptorStatus status = CCCrypt(operation,
										 algorithm,
										 options,
										 key.bytes,
										 key.length,
										 iv.bytes,
										 inputData.bytes,
										 inputData.length,
										 buf,
										 bufSize,
										 &dataOutMoved);
		NSData *outData = nil;
		if (status == kCCSuccess) {
			outData = [NSData dataWithBytes:buf length:dataOutMoved];
		} else {
			perror(__PRETTY_FUNCTION__);
		}
		free(buf);
		buf = NULL;
		return outData;
	}
	return nil;
}
@end

