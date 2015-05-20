//
//  INBTripleDES.m
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import "INBTripleDES.h"
#import "NSData+INB.h"

@implementation INBTripleDES

static INBTripleDES *sharedINBTripleDES = nil;

+ (instancetype)sharedINBTripleDES {
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		sharedINBTripleDES = [[super allocWithZone:NULL] init];
		[sharedINBTripleDES updateKey];
		[sharedINBTripleDES updateIV];
	});
	return sharedINBTripleDES;
}

+ (id)allocWithZone:(struct _NSZone *)zone {
	return [INBTripleDES sharedINBTripleDES];
}

- (void)updateKey {
	_key = [NSData generateSymmetricKeyForAlgorithm:kCCAlgorithm3DES
											keySize:kCCKeySize3DES];;
}

- (void)updateIV {
	_iv = [NSData generateIVForAlgorithm:kCCAlgorithm3DES];
}

- (NSData *)tripleDESEncrypt:(NSData *)plainData {
	return [self doCipher:plainData
				operation:kCCEncrypt];
}

- (NSData *)tripleDESDecrypt:(NSData *)cipherData {
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
		unsigned char bytes[kCCBlockSize3DES] = {0};
		_iv = [NSData dataWithBytes:bytes length:kCCBlockSize3DES];
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
	return [data doBlockCipherWithAlgorithm:kCCAlgorithm3DES
										key:self.key
										 iv:self.iv
								  operation:operation
							 isPKCS7Padding:isPKCS7Padding];
}
@end
