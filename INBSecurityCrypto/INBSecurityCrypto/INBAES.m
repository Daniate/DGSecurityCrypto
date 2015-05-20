//
//  INBAES.m
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import "INBAES.h"
#import "NSData+INB.h"

@implementation INBAES

static INBAES *sharedINBAES = nil;

+ (instancetype)sharedINBAES {
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		sharedINBAES = [[super allocWithZone:NULL] init];
		[sharedINBAES updateKeyWithKeySize:kCCKeySizeAES256];
		[sharedINBAES updateIV];
	});
	return sharedINBAES;
}

+ (id)allocWithZone:(struct _NSZone *)zone {
	return [INBAES sharedINBAES];
}

- (void)updateKeyWithKeySize:(unsigned int)keySize {
	NSParameterAssert(keySize == kCCKeySizeAES128 ||
					  keySize == kCCKeySizeAES192 ||
					  keySize == kCCKeySizeAES256);
	_key = [NSData generateSymmetricKeyForAlgorithm:kCCAlgorithmAES
											keySize:keySize];
}

- (void)updateIV {
	_iv = [NSData generateIVForAlgorithm:kCCAlgorithmAES];
}

- (NSData *)AES128Encrypt:(NSData *)plainData {
	if (self.key.length != kCCKeySizeAES128) {
		[self updateKeyWithKeySize:kCCKeySizeAES128];
	}
	return [self doCipher:plainData
				operation:kCCEncrypt];
}

- (NSData *)AES128Decrypt:(NSData *)cipherData {
	return [self doCipher:cipherData
				operation:kCCDecrypt];
}

- (NSData *)AES192Encrypt:(NSData *)plainData {
	if (self.key.length != kCCKeySizeAES192) {
		[self updateKeyWithKeySize:kCCKeySizeAES192];
	}
	return [self doCipher:plainData
				operation:kCCEncrypt];
}
- (NSData *)AES192Decrypt:(NSData *)cipherData {
	return [self doCipher:cipherData
				operation:kCCDecrypt];
}
- (NSData *)AES256Encrypt:(NSData *)plainData {
	if (self.key.length != kCCKeySizeAES256) {
		[self updateKeyWithKeySize:kCCKeySizeAES256];
	}
	return [self doCipher:plainData
				operation:kCCEncrypt];
}
- (NSData *)AES256Decrypt:(NSData *)cipherData {
	return [self doCipher:cipherData
				operation:kCCDecrypt];
}

- (NSData *)doCipher:(NSData *)data
				 key:(NSData *)key
				  iv:(NSData *)iv
		   operation:(CCOperation)operation {
	_key = key;
	if (iv) {
		_iv = iv;
	} else {
		unsigned char bytes[kCCBlockSizeAES128] = {0};
		_iv = [NSData dataWithBytes:bytes length:kCCBlockSizeAES128];
	}
	return [self doCipher:data
				operation:operation];
}

#pragma mark - Private Methods
- (NSData *)doCipher:(NSData *)data
		   operation:(CCOperation)operation {
	return [self doCipher:data
				operation:operation
		   isPKCS7Padding:YES];
}
- (NSData *)doCipher:(NSData *)data
		   operation:(CCOperation)operation
	  isPKCS7Padding:(BOOL)isPKCS7Padding {
	return [data doBlockCipherWithAlgorithm:kCCAlgorithmAES
										key:self.key
										 iv:self.iv
								  operation:operation
							 isPKCS7Padding:isPKCS7Padding];
}
@end
