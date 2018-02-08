//
//  DGTripleDES.m
//  DGSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import "DGTripleDES.h"
#import "NSData+DGSecurityCrypto.h"

@implementation DGTripleDES

static DGTripleDES *sharedDGTripleDES = nil;

+ (nonnull instancetype)sharedDGTripleDES {
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		sharedDGTripleDES = [[super allocWithZone:NULL] init];
		[sharedDGTripleDES updateKey];
		[sharedDGTripleDES updateIV];
	});
	return sharedDGTripleDES;
}

+ (id)allocWithZone:(struct _NSZone *)zone {
	return [DGTripleDES sharedDGTripleDES];
}

- (void)updateKey {
	_key = [NSData dg_generateSymmetricKeyForAlgorithm:kCCAlgorithm3DES keySize:kCCKeySize3DES];;
}

- (void)updateIV {
	_iv = [NSData dg_generateIVForAlgorithm:kCCAlgorithm3DES];
}

- (NSData * _Nullable)tripleDESEncrypt:(NSData * _Nonnull)plainData {
	return [self _doCipher:plainData operation:kCCEncrypt];
}

- (NSData * _Nullable)tripleDESDecrypt:(NSData * _Nonnull)cipherData {
	return [self _doCipher:cipherData operation:kCCDecrypt];
}

- (NSData * _Nullable)doCipher:(NSData * _Nonnull)data
                           key:(NSData * _Nonnull)key
                            iv:(NSData * _Nullable)iv
                     operation:(CCOperation)operation {
	_key = key;
	if (iv) {
		_iv = iv;
	} else {
		unsigned char bytes[kCCBlockSize3DES] = {'\0'};
		_iv = [NSData dataWithBytes:bytes length:kCCBlockSize3DES];
	}
	return [self _doCipher:data operation:operation];
}

#pragma mark - Private Methods
- (NSData * _Nullable)_doCipher:(NSData * _Nonnull)data
                      operation:(CCOperation)operation {
	return [self _doCipher:data operation:operation isPKCS7Padding:YES];
}

- (NSData * _Nullable)_doCipher:(NSData * _Nonnull)data
                      operation:(CCOperation)operation
                 isPKCS7Padding:(BOOL)isPKCS7Padding {
	return [data dg_doBlockCipherWithAlgorithm:kCCAlgorithm3DES
                                           key:self.key
                                            iv:self.iv
                                     operation:operation
                                isPKCS7Padding:isPKCS7Padding];
}
@end
