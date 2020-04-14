#import <Foundation/Foundation.h>

@interface NSData (Hex)

- (NSString*)hexString;
- (NSString*)hexStringWithCaps:(BOOL)caps;
+ (NSData*)dataWithHexString:(NSString*)hexString;

@end
