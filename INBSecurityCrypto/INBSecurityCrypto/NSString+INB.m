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

- (NSString *)encodeToHexString {
	return [[self dataUsingEncoding:NSUTF8StringEncoding] encodeToHexString];
}

- (NSString *)decodeFromHexString {
	return [[NSString alloc] initWithData:[[self dataUsingEncoding:NSUTF8StringEncoding] decodeFromHexData] encoding:NSUTF8StringEncoding];
}
@end