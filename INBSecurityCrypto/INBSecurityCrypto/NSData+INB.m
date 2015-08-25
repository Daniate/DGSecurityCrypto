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
		return [self base64EncodedStringWithOptions:0];
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
		return [self base64EncodedDataWithOptions:0];
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
static const char *digitsHex = "0123456789abcdef";
//static const char *digitsHex = "0123456789ABCDEF";
- (NSData *)encodeToHexData {
    NSData *encodedData = nil;
    if (self) {
        NSUInteger len = self.length;
        unsigned char *bytes = (unsigned char *)self.bytes;
        size_t bufSize = (len << 1);
        unsigned char *buf = malloc(bufSize);
        if (buf) {
            memset(buf, 0x0, bufSize);
            for (NSUInteger i = 0, j = 0; i < len; i++) {
                buf[j] = *(digitsHex + ((0xF0 & bytes[i]) >> 4));
                j++;
                buf[j] = *(digitsHex + (0x0F & bytes[i]));
                j++;
            }
            encodedData = [NSData dataWithBytes:buf length:bufSize];
            free(buf);
            buf = NULL;
        }
    }
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
    NSData *decodedData = nil;
    if (self) {
        NSUInteger len = self.length;
        NSAssert((len & 0x1) == 0x0, @"数据长度必须是偶数");
        unsigned char *bytes = (unsigned char *)self.bytes;
        NSUInteger bufSize = (len >> 1) * sizeof(unsigned char);
        unsigned char *buf = malloc(bufSize);
        if (buf) {
            memset(buf, 0x0, bufSize);
            for (NSUInteger i = 0, j = 0; i < len; j++) {
                unsigned char f = numberFromHex(bytes[i]) << 4;
                i++;
                f |= numberFromHex(bytes[i]);
                i++;
                buf[j] = f;
            }
            decodedData = [NSData dataWithBytes:buf length:bufSize];
            free(buf);
            buf = NULL;
        }
    }
    return decodedData;
}

- (NSString *)encodeToHexString {
	return [[NSString alloc] initWithData:[self encodeToHexData]
								 encoding:NSUTF8StringEncoding];
}
@end

@implementation NSData (INBCryptoPRNG)

+ (NSData *)generateSecureRandomData:(size_t)length {
	NSData *randomData = nil;
	void *buf = malloc(length);
	if (buf) {
		memset(buf, 0x0, length);
#ifdef __IPHONE_8_0
		if (INBIOS8_0_0OrLater) {
			if (CCRandomGenerateBytes(buf, length) == kCCSuccess) {
				randomData = [NSData dataWithBytes:buf length:length];
			} else {
				perror(__PRETTY_FUNCTION__);
			}
		} else {
#endif
			if (SecRandomCopyBytes(kSecRandomDefault, length, buf) == 0) {
				randomData = [NSData dataWithBytes:buf length:length];
			} else {
				perror(__PRETTY_FUNCTION__);
			}
#ifdef __IPHONE_8_0
		}
#endif
		free(buf);
		buf = NULL;
	}
	return randomData;
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
	return [NSData generateSecureRandomData:keySize];
}

- (NSData *)HmacWithAlgorithm:(CCHmacAlgorithm)algorithm key:(NSData *)key {
	NSParameterAssert(algorithm == kCCHmacAlgSHA1 ||
					  algorithm == kCCHmacAlgMD5 ||
					  algorithm == kCCHmacAlgSHA256 ||
					  algorithm == kCCHmacAlgSHA384 ||
					  algorithm == kCCHmacAlgSHA512 ||
					  algorithm == kCCHmacAlgSHA224);
	NSParameterAssert(key != nil);
	unsigned char buf[CC_SHA512_DIGEST_LENGTH] = {0x0};
	CCHmac(algorithm, key.bytes, key.length, self.bytes, self.length, buf);
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
	return [NSData generateSymmetricKeyForAlgorithm:algorithm keySize:keySize];
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
	return [NSData generateSecureRandomData:keySize];
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
	return [NSData generateSecureRandomData:ivSize];
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
/**
 *  额外的填充长度，针对NoPadding。由于是全局变量，
 *  所以，如果使用了NoPadding，尽量不要在多线程中同时多次调用相关方法。
 */
NSUInteger extraPaddingLength = 0;

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
	NSData *outData = nil;
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
			// 对于NoPadding，需要手动将原始数据的长度补足为分组大小的整数倍
			extraPaddingLength = blockSize - tmp;
			bufSize += extraPaddingLength;
			inputData = padding(self, blockSize);
		}
		void *buf = malloc(bufSize);
		if (buf) {
			memset(buf, 0x0, bufSize);
			CCOptions options = 0;
			if (isPKCS7Padding) {
				options |= kCCOptionPKCS7Padding;
			}
			if (isECB) {
				options |= kCCOptionECBMode;
			}
			size_t dataOutMoved = 0;
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
			
			if (status == kCCSuccess) {
				if (operation == kCCDecrypt && extraPaddingLength > 0) {
					dataOutMoved -= extraPaddingLength;
					extraPaddingLength = 0;
				}
				outData = [NSData dataWithBytes:buf length:dataOutMoved];
			} else {
				perror(__PRETTY_FUNCTION__);
			}
			free(buf);
			buf = NULL;
		}
	}
	return outData;
}
@end

