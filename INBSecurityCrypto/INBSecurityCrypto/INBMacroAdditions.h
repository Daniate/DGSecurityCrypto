//
//  INBMacroAdditions.h
//  INBSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#ifndef INBMacroAdditions_h
#define INBMacroAdditions_h

#import <UIKit/UIKit.h>

#define INBIsSysVersionGreaterThanOrEqualTo(__VERSION_STRING__) ([[[UIDevice currentDevice] systemVersion] compare:(__VERSION_STRING__) options:NSNumericSearch] != NSOrderedAscending)

#define INBIOS7_0_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"7.0.0")
#define INBIOS8_0_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"8.0.0")

#endif
