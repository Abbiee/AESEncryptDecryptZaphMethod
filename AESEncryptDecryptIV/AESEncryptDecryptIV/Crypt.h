//
//  Crypt.h
//  AESEncryptDecryptIV
//
//  Created by Abbie on 02/11/20.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

NS_ASSUME_NONNULL_BEGIN

@interface Crypt : NSObject
+ (NSData *)aes128Data:(NSData *)dataIn
             operation:(CCOperation)operation  // kCC Encrypt, Decrypt
                   key:(NSData *)key
               options:(CCOptions)options      // kCCOption PKCS7Padding, ECBMode,
                    iv:(NSData *)iv
                 error:(NSError **)error;
+ (NSData *)dataFromHexString:(NSString *)hexString;
@end

NS_ASSUME_NONNULL_END
