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
- (NSString * _Nullable)dg_base64EncodedString {
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
- (NSData * _Nullable)dg_base64EncodedData {
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
+ (NSData * _Nullable)dg_base64DecodedDataWithString:(NSString *)base64String {
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
+ (NSData * _Nullable)dg_base64DecodedDataWithData:(NSData *)base64Data {
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
- (NSData * _Nullable)dg_base64DecodedData {
	return [NSData dg_base64DecodedDataWithData:self];
}
@end

@implementation NSData (INBMessageDigest)
- (NSData * _Nullable)dg_MD2 {
	unsigned char md[CC_MD2_DIGEST_LENGTH] = {'\0'};
	CC_MD2(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_MD2_DIGEST_LENGTH];
}
- (NSData * _Nullable)dg_MD4 {
	unsigned char md[CC_MD4_DIGEST_LENGTH] = {'\0'};
	CC_MD4(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_MD4_DIGEST_LENGTH];
}
- (NSData * _Nullable)dg_MD5 {
	unsigned char md[CC_MD5_DIGEST_LENGTH] = {'\0'};
	CC_MD5(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_MD5_DIGEST_LENGTH];
}
- (NSData * _Nullable)dg_SHA1 {
	unsigned char md[CC_SHA1_DIGEST_LENGTH] = {'\0'};
	CC_SHA1(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA1_DIGEST_LENGTH];
}
- (NSData * _Nullable)dg_SHA224 {
	unsigned char md[CC_SHA224_DIGEST_LENGTH] = {'\0'};
	CC_SHA224(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA224_DIGEST_LENGTH];
}
- (NSData * _Nullable)dg_SHA256 {
	unsigned char md[CC_SHA256_DIGEST_LENGTH] = {'\0'};
	CC_SHA256(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA256_DIGEST_LENGTH];
}
- (NSData * _Nullable)dg_SHA384 {
	unsigned char md[CC_SHA384_DIGEST_LENGTH] = {'\0'};
	CC_SHA384(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA384_DIGEST_LENGTH];
}
- (NSData * _Nullable)dg_SHA512 {
	unsigned char md[CC_SHA512_DIGEST_LENGTH] = {'\0'};
	CC_SHA512(self.bytes, (CC_LONG)self.length, md);
	return [NSData dataWithBytes:md length:CC_SHA512_DIGEST_LENGTH];
}
@end

@implementation NSData (INBHex)
static const char *__dg_sc_digitsHex = "0123456789abcdef";
//static const char *__dg_sc_digitsHex = "0123456789ABCDEF";
- (NSData * _Nullable)dg_encodeToHexData {
    NSUInteger len = self.length;
    size_t bufSize = (len << 1) * sizeof(unsigned char);
    unsigned char *buf = malloc(bufSize);
    if (buf == NULL) {
        NSLog(@"%s (Cannot alloc memory.)", __PRETTY_FUNCTION__);
        return nil;
    }
    memset(buf, '\0', bufSize);
    unsigned char *bytes = (unsigned char *)self.bytes;
    for (NSUInteger i = 0, j = 0; i < len; i++) {
        buf[j] = *(__dg_sc_digitsHex + ((0xF0 & bytes[i]) >> 4));
        j++;
        buf[j] = *(__dg_sc_digitsHex + (0x0F & bytes[i]));
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
static int dg_numberFromHex(unsigned char hex) {
	if (hex >= '0' && hex <= '9') {
		return hex - '0';
	}
	if (hex >= 'a' && hex <= 'f') {
		return hex - 'a' + 10;
	}
	if (hex >= 'A' && hex <= 'F') {
		return hex - 'A' + 10;
	}
    NSLog(@"%s (Invalid hex character: %c.)", __PRETTY_FUNCTION__, hex);
	return 0;
}

- (NSData * _Nullable)dg_decodeFromHexData {
    NSUInteger len = self.length;
    if ((len & 0x1) != 0x0) {
        NSLog(@"%s (Hex data's length must be an even number.)", __PRETTY_FUNCTION__);
        return nil;
    }
    NSUInteger bufSize = (len >> 1) * sizeof(unsigned char);
    unsigned char *buf = malloc(bufSize);
    if (buf == NULL) {
        NSLog(@"%s (Cannot alloc memory.)", __PRETTY_FUNCTION__);
        return nil;
    }
    memset(buf, '\0', bufSize);
    unsigned char *bytes = (unsigned char *)self.bytes;
    for (NSUInteger i = 0, j = 0; i < len; j++) {
        unsigned char f = dg_numberFromHex(bytes[i]) << 4;
        i++;
        f |= dg_numberFromHex(bytes[i]);
        i++;
        buf[j] = f;
    }
    NSData *decodedData = [NSData dataWithBytes:buf length:bufSize];
    free(buf);
    buf = NULL;
    return decodedData;
}

- (NSString * _Nullable)dg_encodeToHexString {
	return [[NSString alloc] initWithData:[self dg_encodeToHexData]
								 encoding:NSUTF8StringEncoding];
}
@end

@implementation NSData (INBMDSHAHexString)

- (NSString * _Nullable)dg_MD2HexString {
    return [[self dg_MD2] dg_encodeToHexString];
}

- (NSString * _Nullable)dg_MD4HexString {
    return [[self dg_MD4] dg_encodeToHexString];
}

- (NSString * _Nullable)dg_MD5HexString {
    return [[self dg_MD5] dg_encodeToHexString];
}

- (NSString * _Nullable)dg_SHA1HexString {
    return [[self dg_SHA1] dg_encodeToHexString];
}

- (NSString * _Nullable)dg_SHA224HexString {
    return [[self dg_SHA224] dg_encodeToHexString];
}

- (NSString * _Nullable)dg_SHA256HexString {
    return [[self dg_SHA256] dg_encodeToHexString];
}

- (NSString * _Nullable)dg_SHA384HexString {
    return [[self dg_SHA384] dg_encodeToHexString];
}

- (NSString * _Nullable)dg_SHA512HexString {
    return [[self dg_SHA512] dg_encodeToHexString];
}

@end

@implementation NSData (INBCryptoPRNG)

+ (NSData * _Nullable)dg_generateSecureRandomData:(size_t)length {
    if (length == 0) {
        NSLog(@"%s (Length should not be zero.)", __PRETTY_FUNCTION__);
        return nil;
    }
	void *buf = malloc(length);
    if (buf == NULL) {
        NSLog(@"%s (Cannot alloc memory.)", __PRETTY_FUNCTION__);
        return nil;
    }
    NSData *randomData = nil;
    memset(buf, '\0', length);
#ifdef __IPHONE_8_0
    if (INBIOS8_0_0OrLater) {
        if (CCRandomGenerateBytes(buf, length) == kCCSuccess) {
            randomData = [NSData dataWithBytes:buf length:length];
        } else {
            NSLog(@"%s (CCRandomGenerateBytes failed.)", __PRETTY_FUNCTION__);
        }
    } else {
#endif
        if (SecRandomCopyBytes(kSecRandomDefault, length, buf) == 0) {
            randomData = [NSData dataWithBytes:buf length:length];
        } else {
            NSLog(@"%s (SecRandomCopyBytes failed.)", __PRETTY_FUNCTION__);
        }
#ifdef __IPHONE_8_0
    }
#endif
    free(buf);
    buf = NULL;
	return randomData;
}

@end

@implementation NSData (INBHmac)
+ (NSData * _Nullable)dg_generateHmacKeyForAlgorithm:(CCHmacAlgorithm)algorithm {
	size_t keySize = 0;
	switch (algorithm) {
        case kCCHmacAlgMD5:
            keySize = CC_MD5_DIGEST_LENGTH;
            break;
		case kCCHmacAlgSHA1:
			keySize = CC_SHA1_DIGEST_LENGTH;
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
            NSLog(@"%s (The algorithm is invalid.)", __PRETTY_FUNCTION__);
            return nil;
	}
	return [NSData dg_generateSecureRandomData:keySize];
}

- (NSData * _Nullable)dg_HmacWithAlgorithm:(CCHmacAlgorithm)algorithm key:(NSData * _Nonnull)key {
    if (key == nil) {
        NSLog(@"Key must not be nil.");
        return nil;
    }
	NSUInteger length = 0;
	switch (algorithm) {
        case kCCHmacAlgMD5:
            length = CC_MD5_DIGEST_LENGTH;
            break;
		case kCCHmacAlgSHA1:
			length = CC_SHA1_DIGEST_LENGTH;
			break;
        case kCCHmacAlgSHA224:
            length = CC_SHA224_DIGEST_LENGTH;
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
		default:
            NSLog(@"%s (The algorithm is invalid.)", __PRETTY_FUNCTION__);
            return nil;
	}
    unsigned char buf[CC_SHA512_DIGEST_LENGTH] = {'\0'};
    CCHmac(algorithm, key.bytes, key.length, self.bytes, self.length, buf);
	return [NSData dataWithBytes:buf length:length];
}
@end

@implementation NSData (INBSymmetricKeyGenerator)
+ (NSData *)dg_generateSymmetricKeyForAlgorithm:(CCAlgorithm)algorithm {
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
		default:// kCCAlgorithmAES128 / kCCAlgorithmAES
            NSLog(@"%s (The algorithm is invalid. Assume kCCAlgorithmAES128/kCCAlgorithmAES.)", __PRETTY_FUNCTION__);
			keySize = kCCKeySizeAES256;
			break;
	}
	return [NSData dg_generateSymmetricKeyForAlgorithm:algorithm keySize:keySize];
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
+ (NSData * _Nullable)dg_generateSymmetricKeyForAlgorithm:(CCAlgorithm)algorithm
                                                  keySize:(unsigned int)keySize {
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
		default:// kCCAlgorithmAES128 / kCCAlgorithmAES
            NSLog(@"%s (The algorithm is invalid. Assume kCCAlgorithmAES128/kCCAlgorithmAES.)", __PRETTY_FUNCTION__);
			if (keySize <= kCCKeySizeAES128) {
				keySize = kCCKeySizeAES128;
			} else if (keySize <= kCCKeySizeAES192) {
				keySize = kCCKeySizeAES192;
			} else {
				keySize = kCCKeySizeAES256;
			}
			break;
	}
	return [NSData dg_generateSecureRandomData:keySize];
}
@end

@implementation NSData (INBIVGenerator)
+ (NSData * _Nullable)dg_generateIVForAlgorithm:(CCAlgorithm)algorithm {
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
		default:// kCCAlgorithmAES128 / kCCAlgorithmAES
            NSLog(@"%s (The algorithm is invalid. Assume kCCAlgorithmAES128/kCCAlgorithmAES.)", __PRETTY_FUNCTION__);
			ivSize = kCCBlockSizeAES128;
			break;
	}
	return [NSData dg_generateSecureRandomData:ivSize];
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
static NSData * _Nullable dg_padding(NSData * _Nullable data, size_t blockSize) {
	NSCParameterAssert(blockSize == kCCBlockSizeAES128 ||
					   blockSize == kCCBlockSizeDES ||
					   blockSize == kCCBlockSize3DES ||
					   blockSize == kCCBlockSizeCAST ||
					   blockSize == kCCBlockSizeRC2 ||
					   blockSize == kCCBlockSizeBlowfish);
    if (data == nil) {
        return nil;
    }
	NSUInteger remainder = data.length % blockSize;
    if (remainder == 0) {
        return data;
    }
    NSMutableData *expectedData = [data mutableCopy];
    [expectedData increaseLengthBy:(blockSize - remainder)];
    return [NSData dataWithData:expectedData];
}

- (NSData * _Nullable)dg_doBlockCipherWithAlgorithm:(CCAlgorithm)algorithm
                                                key:(NSData * _Nonnull)key
                                                 iv:(NSData * _Nullable)iv
                                          operation:(CCOperation)operation
                                     isPKCS7Padding:(BOOL)isPKCS7Padding {
	return [self dg_doBlockCipherWithAlgorithm:algorithm
                                           key:key
                                            iv:iv
                                     operation:operation
                                isPKCS7Padding:isPKCS7Padding
                                         isECB:NO];
}
/**
 *  额外的填充长度，针对NoPadding。
 *  由于是全局变量，所以，如果使用了NoPadding，尽量不要在多线程中使用相关方法。
 */
NSUInteger __dg_sc_extraPaddingLength = 0;

- (NSData * _Nullable)dg_doBlockCipherWithAlgorithm:(CCAlgorithm)algorithm
                                                key:(NSData * _Nonnull)key
                                                 iv:(NSData * _Nullable)iv
                                          operation:(CCOperation)operation
                                     isPKCS7Padding:(BOOL)isPKCS7Padding
                                              isECB:(BOOL)isECB {
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
		default:// kCCAlgorithmAES128 / kCCAlgorithmAES
            NSLog(@"%s (The algorithm is invalid. Assume kCCAlgorithmAES128/kCCAlgorithmAES.)", __PRETTY_FUNCTION__);
			NSParameterAssert(key.length == kCCKeySizeAES128 ||
							  key.length == kCCKeySizeAES192 ||
							  key.length == kCCKeySizeAES256);
			NSParameterAssert(iv == nil || iv.length == kCCBlockSizeAES128);
			break;
	}
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
        default:// kCCAlgorithmAES128 / kCCAlgorithmAES
            NSLog(@"%s (The algorithm is invalid. Assume kCCAlgorithmAES128/kCCAlgorithmAES.)", __PRETTY_FUNCTION__);
            blockSize = kCCBlockSizeAES128;
            break;
    }
    NSUInteger len = self.length;
    NSData *inputData = self;
    size_t bufSize = len + blockSize;
    size_t remainder = len % blockSize;
    if (!isPKCS7Padding && remainder != 0) {
        // 对于NoPadding，需要手动将原始数据的长度补足为分组大小的整数倍
        __dg_sc_extraPaddingLength = blockSize - remainder;
        bufSize += __dg_sc_extraPaddingLength;
        inputData = dg_padding(self, blockSize);
    }
    void *buf = malloc(bufSize);
    if (buf == NULL) {
        NSLog(@"%s (Cannot alloc memory.)", __PRETTY_FUNCTION__);
        return nil;
    }
    memset(buf, '\0', bufSize);
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
    if (status != kCCSuccess) {
        free(buf);
        buf = NULL;
        NSLog(@"%s (CCCrypt failed.)", __PRETTY_FUNCTION__);
        return nil;
    }
    if (operation == kCCDecrypt && __dg_sc_extraPaddingLength > 0) {
        dataOutMoved -= __dg_sc_extraPaddingLength;
        __dg_sc_extraPaddingLength = 0;
    }
    NSData *outData = [NSData dataWithBytes:buf length:dataOutMoved];
    free(buf);
    buf = NULL;
	return outData;
}
@end

