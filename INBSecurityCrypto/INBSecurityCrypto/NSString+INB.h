//
//  NSString+INB.h
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import <UIKit/UIKit.h>
/**
 *  对字符串进行十六进制编解码，使用小写字母
 */
@interface NSString (INBHex)
/**
 *  获取NSString对应的十六进制字符串
 *
 *  @return 十六进制字符串
 */
- (NSString *)encodeToHexString;
/**
 *  对调用`- (NSString *)encodeToHexString`得到的字符串进行还原
 *
 *  @return 还原后的NSString
 */
- (NSString *)decodeFromHexString;
@end
