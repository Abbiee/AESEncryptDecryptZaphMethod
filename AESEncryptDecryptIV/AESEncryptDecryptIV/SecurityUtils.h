//
//  SecurityUtils.h
//
//  Created by Abbie on 02/11/20.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>

NS_ASSUME_NONNULL_BEGIN

@interface SecurityUtils : NSObject

+ (NSString *)encrypt:(NSString *)plainText error:(NSError **)error;
+ (NSString *)decrypt:(NSString *)plainText error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
