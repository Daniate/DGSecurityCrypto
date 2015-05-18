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

#define INBIsSysVersionGreaterThan(__VERSION_STRING__)          ([[[UIDevice currentDevice] systemVersion] compare:(__VERSION_STRING__) options:NSNumericSearch] == NSOrderedDescending)
#define INBIsSysVersionGreaterThanOrEqualTo(__VERSION_STRING__) ([[[UIDevice currentDevice] systemVersion] compare:(__VERSION_STRING__) options:NSNumericSearch] != NSOrderedAscending)
#define INBIsSysVersionLessThan(__VERSION_STRING__)             ([[[UIDevice currentDevice] systemVersion] compare:(__VERSION_STRING__) options:NSNumericSearch] == NSOrderedAscending)
#define INBIsSysVersionLessThanOrEqualTo(__VERSION_STRING__)    ([[[UIDevice currentDevice] systemVersion] compare:(__VERSION_STRING__) options:NSNumericSearch] != NSOrderedDescending)

#define INBIOS6_0_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"6.0")
#define INBIOS6_1_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"6.1")
#define INBIOS7_0_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"7.0")
#define INBIOS7_1_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"7.1")
#define INBIOS8_0_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"8.0")
#define INBIOS8_1_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"8.1")
#define INBIOS8_1_1OrLater INBIsSysVersionGreaterThanOrEqualTo(@"8.1.1")
#define INBIOS8_2_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"8.2")
#define INBIOS8_3_0OrLater INBIsSysVersionGreaterThanOrEqualTo(@"8.3")

#endif
