//
//  NSString+hex.h
//  Created by Ben Baron on 10/20/10.
//
#import <Foundation/Foundation.h>

@interface NSString (hex)

    + (NSString *) stringFromHex:(NSString *)str;
    + (NSString *) stringToHex:(NSString *)str;

@end
