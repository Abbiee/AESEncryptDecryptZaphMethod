//
//  Crypt.m
//  AESEncryptDecryptIV
//
//  Created by Abbie on 02/11/20.
//

#import "Crypt.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@implementation Crypt
+ (NSData *)aes128Data:(NSData *)dataIn
             operation:(CCOperation)operation  // kCC Encrypt, Decrypt
                   key:(NSData *)key
               options:(CCOptions)options      // kCCOption PKCS7Padding, ECBMode,
                    iv:(NSData *)iv
                 error:(NSError **)error
{
    CCCryptorStatus ccStatus   = kCCSuccess;
    size_t          cryptBytes = 0;
    NSMutableData  *dataOut    = [NSMutableData dataWithLength:dataIn.length + kCCBlockSizeAES128];

    ccStatus = CCCrypt( operation,
                       kCCAlgorithmAES,
                       options,
                       key.bytes, key.length,
                       iv.bytes,
                       dataIn.bytes, dataIn.length,
                       dataOut.mutableBytes, dataOut.length,
                       &cryptBytes);

    if (ccStatus == kCCSuccess) {
        dataOut.length = cryptBytes;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:@"kEncryptionError"
                                         code:ccStatus
                                     userInfo:nil];
        }
        dataOut = nil;
    }

    return dataOut;
}

+ (NSData *)dataFromHexString:(NSString *)hexString {
    char buf[3];
    buf[2] = '\0';
    unsigned char *bytes = malloc([hexString length]/2);
    unsigned char *bp = bytes;
    for (CFIndex i = 0; i < [hexString length]; i += 2) {
        buf[0] = [hexString characterAtIndex:i];
        buf[1] = [hexString characterAtIndex:i+1];
        char *b2 = NULL;
        *bp++ = strtol(buf, &b2, 16);
    }

    return [NSData dataWithBytesNoCopy:bytes length:[hexString length]/2 freeWhenDone:YES];
}

@end
