//
//  DGMacroAdditions.h
//  DGSecurityCrypto
//
//  Created by Daniate on 15/3/12.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#ifndef DGMacroAdditions_h
#define DGMacroAdditions_h

#import <UIKit/UIKit.h>

#define DGIsSysVersionGreaterThanOrEqualTo(__VERSION_STRING__) ([[[UIDevice currentDevice] systemVersion] compare:(__VERSION_STRING__) options:NSNumericSearch] != NSOrderedAscending)

#define DGIOS7_0_0OrLater DGIsSysVersionGreaterThanOrEqualTo(@"7.0.0")
#define DGIOS8_0_0OrLater DGIsSysVersionGreaterThanOrEqualTo(@"8.0.0")

#endif
