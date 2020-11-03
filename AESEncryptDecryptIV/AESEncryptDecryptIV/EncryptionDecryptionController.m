//
//  EncryptionDecryptionController.m
//  AESEncryptDecryptIV
//
//  Created by Abbie on 02/11/20.
//

#import "EncryptionDecryptionController.h"
#import "Crypt.h"
#import "SecurityUtils.h"
#import "FBEncryptorAES.h"

@interface EncryptionDecryptionController ()
{
   // CryptLib *cryptingInstance;
    NSData *encryptedText;
    NSString *encrypted;
}

@end

@implementation EncryptionDecryptionController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
}
- (IBAction)encryptAction:(id)sender {

// ZAPH User Stackoveflow Encrypt decrypt Logic
    NSError *error;
//    NSData *AESKeyData = [EncryptionDecryptionController random128BitAESKey];
//    NSData *key   = [@"Bad example key " dataUsingEncoding:NSUTF8StringEncoding];
    NSData *AESKeyData = [EncryptionDecryptionController randomDataOfLength:16];
    NSData *clear = [@"In a storyboard-based application, you will often want to do a little preparation before navigation"       dataUsingEncoding:NSUTF8StringEncoding];

//    NSData *encrypted = [EncryptionDecryptionController aesCBCEncrypt:clear
//                                             key:AESKeyData
//                                           error:&error];
    
    NSData *encrypted = [EncryptionDecryptionController aesCBCEncrypt:clear
                                             key:AESKeyData
                                           error:&error];

    NSData *decrypted = [EncryptionDecryptionController aesCBCDecrypt:encrypted
                                             key:AESKeyData
                                           error:&error];

    NSLog(@"key:       %@", AESKeyData);
    NSLog(@"clear:     %@", clear);
    NSLog(@"encrypted: %@", encrypted);
    NSLog(@"Encrypted Base 64: %@", [encrypted base64EncodedStringWithOptions:0]);
    NSLog(@"decrypted: %@", decrypted);
    NSLog(@"decrypted: %@", [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding]);
}
- (IBAction)decryptAction:(id)sender {
//    NSString* msg = [FBEncryptorAES decryptBase64String:encrypted                                               keyString:@"9336365521W5F092BB5909E8E033BC69"];
//
//    if (msg) {
//      //  NSLog(@"decrypted: %@", msg);
//    } else {
//       // NSLog(@"failed to decrypt");
//    }
}

/*
#pragma mark - Navigation

// In a storyboard-based application, you will often want to do a little preparation before navigation
- (void)prepareForSegue:(UIStoryboardSegue *)segue sender:(id)sender {
    // Get the new view controller using [segue destinationViewController].
    // Pass the selected object to the new view controller.
}
*/

// Creating random key by using arc4random_buf(less preferrable) https://stackoverflow.com/questions/23531515/create-random-128-bit-aes-encryption-key-in-ios

+ (NSData *)random128BitAESKey {
    unsigned char buf[16];
    arc4random_buf(buf, sizeof(buf));
    return [NSData dataWithBytes:buf length:sizeof(buf)];
}

// Creating random key by using SecRandomCopyBytes(Most preferrable).. Refer FBEncryptor.m

+ (NSData *)randomDataOfLength:(size_t)length {
  NSMutableData *data = [NSMutableData dataWithLength:length];

  int result = SecRandomCopyBytes(kSecRandomDefault,
                                  length,
                                  data.mutableBytes);
  NSAssert(result == 0, @"Unable to generate random bytes: %d",
           errno);

  return data;
}

+ (NSData *)aesCBCEncrypt:(NSData *)data
                         key:(NSData *)key
                       error:(NSError **)error
{
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        *error = [NSError errorWithDomain:@"keyLengthError" code:-1 userInfo:nil];
        return nil;
    }

    CCCryptorStatus ccStatus   = kCCSuccess;
    int             ivLength   = kCCBlockSizeAES128;
    size_t          cryptBytes = 0;
    NSMutableData  *dataOut     = [NSMutableData dataWithLength:ivLength + data.length + kCCBlockSizeAES128];

    int status = SecRandomCopyBytes(kSecRandomDefault, ivLength, dataOut.mutableBytes);
    if (status != 0) {
        *error = [NSError errorWithDomain:@"ivError" code:status userInfo:nil];
        return nil;
    }
    ccStatus = CCCrypt(kCCEncrypt,
                       kCCAlgorithmAES,
                       kCCOptionPKCS7Padding,
                       key.bytes, key.length,
                       dataOut.bytes,
                       data.bytes, data.length,
                       dataOut.mutableBytes + ivLength, dataOut.length,
                       &cryptBytes);

    if (ccStatus == kCCSuccess) {
        dataOut.length = cryptBytes + ivLength;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:@"kEncryptionError" code:ccStatus userInfo:nil];
        }
        dataOut = nil;
    }

    return dataOut;
}

+ (NSData *)aesCBCDecrypt:(NSData *)data
                         key:(NSData *)key
                       error:(NSError **)error
{
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        *error = [NSError errorWithDomain:@"keyLengthError" code:-1 userInfo:nil];
        return nil;
    }

    CCCryptorStatus ccStatus   = kCCSuccess;
    int             ivLength   = kCCBlockSizeAES128;
    size_t          clearBytes = 0;
    NSMutableData *dataOut     = [NSMutableData dataWithLength:data.length - ivLength];

    ccStatus = CCCrypt(kCCDecrypt,
                       kCCAlgorithmAES,
                       kCCOptionPKCS7Padding,
                       key.bytes, key.length,
                       data.bytes,
                       data.bytes + ivLength, data.length - ivLength,
                       dataOut.mutableBytes, dataOut.length,
                       &clearBytes);

    if (ccStatus == kCCSuccess) {
        dataOut.length = clearBytes;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:@"kEncryptionError" code:ccStatus userInfo:nil];
        }
        dataOut = nil;
    }

    return dataOut;
}
@end
