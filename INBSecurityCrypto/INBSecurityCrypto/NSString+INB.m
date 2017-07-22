//
//  NSString+INB.m
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import "NSString+INB.h"
#import "NSData+INB.h"

@implementation NSString (INBHex)

- (NSString * _Nullable)dg_encodeToHexString {
	return [[self dataUsingEncoding:NSUTF8StringEncoding] dg_encodeToHexString];
}

- (NSString * _Nullable)dg_decodeFromHexString {
	return [[NSString alloc] initWithData:[[self dataUsingEncoding:NSUTF8StringEncoding] dg_decodeFromHexData] encoding:NSUTF8StringEncoding];
}
@end

@implementation NSString (INBMDSHAHexString)

- (NSString * _Nullable)dg_MD2HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] dg_MD2HexString];
}

- (NSString * _Nullable)dg_MD4HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] dg_MD4HexString];
}

- (NSString * _Nullable)dg_MD5HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] dg_MD5HexString];
}

- (NSString * _Nullable)dg_SHA1HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] dg_SHA1HexString];
}

- (NSString * _Nullable)dg_SHA224HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] dg_SHA224HexString];
}

- (NSString * _Nullable)dg_SHA256HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] dg_SHA256HexString];
}

- (NSString * _Nullable)dg_SHA384HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] dg_SHA384HexString];
}

- (NSString * _Nullable)dg_SHA512HexString {
    return [[self dataUsingEncoding:NSUTF8StringEncoding] dg_SHA512HexString];
}

@end
