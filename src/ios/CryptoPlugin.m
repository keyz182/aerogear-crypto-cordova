/*
 * JBoss, Home of Professional Open Source.
 * Copyright Red Hat, Inc., and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import "CryptoPlugin.h"
#import "AGPBKDF2.h"
#import "AGSecretBox.h"
#import "AGRandomGenerator.h"

@implementation CryptoPlugin

- (void)getRandomValue:(CDVInvokedUrlCommand *)command {
    NSData * data = [AGRandomGenerator randomBytes];
    NSString *value = [self convertDataToString:data];
    CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:value];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)deriveKey:(CDVInvokedUrlCommand *)command {
    NSMutableDictionary *options = [self parseParameters:command];
    NSString *password = [options objectForKey:@"password"];
    NSString *salt = [options objectForKey:@"providedSalt"];
    
    [self.commandDelegate runInBackground:^{
        AGPBKDF2 *agpbkdf2 = [[AGPBKDF2 alloc] init];
        NSMutableDictionary *res = [[NSMutableDictionary alloc]init];
        
        NSData *rawPassword = [agpbkdf2 deriveKey:password salt:[salt dataUsingEncoding:NSASCIIStringEncoding]];

        NSString *encodedPassword = [self convertDataToString:rawPassword];
        
        [res setValue:encodedPassword forKey:@"hash"];
        [res setValue:salt forKey:@"salt"];
        
        CDVPluginResult *pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:res];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)encrypt:(CDVInvokedUrlCommand *)command {
    NSMutableDictionary *options = [self parseParameters:command];
    NSString *key = [options objectForKey:@"key"];
    NSString *iv = [options objectForKey:@"IV"];
    NSString *data = [options objectForKey:@"data"];

    AGSecretBox *cryptoBox = [[AGSecretBox alloc] initWithKey:[self convertStringToData:key]];
    [self.commandDelegate runInBackground:^{
        NSError *error;
        NSData *result = [cryptoBox encrypt:[data dataUsingEncoding:NSUTF8StringEncoding] nonce:[self convertStringToData:iv] error:&error];
        
        CDVPluginResult *pluginResult;
        
        if(error){
            NSString *err = [NSString stringWithFormat:@"Reason: %@/nDescription%@", [error localizedFailureReason], [error localizedDescription]];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:err];
        }else{
            NSString *encodedResult = [self convertDataToString:result];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:encodedResult];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (void)decrypt:(CDVInvokedUrlCommand *)command {
    NSMutableDictionary *options = [self parseParameters:command];
    NSString *key = [options objectForKey:@"key"];
    NSString *iv = [options objectForKey:@"IV"];
    NSString *data = [options objectForKey:@"data"];

    AGSecretBox *cryptoBox = [[AGSecretBox alloc] initWithKey:[self convertStringToData:key]];
    [self.commandDelegate runInBackground:^{
        NSError *error;
        NSData *result = [cryptoBox decrypt:[self convertStringToData:data] nonce:[self convertStringToData:iv] error:&error];
        
        CDVPluginResult *pluginResult;
        
        if(error){
            NSString *err = [NSString stringWithFormat:@"Reason: %@/nDescription%@", [error localizedFailureReason], [error localizedDescription]];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:err];
        }else{
            NSString *encodedResult = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:encodedResult];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

- (NSMutableData *)convertStringToData:(NSString *)hexString {
    NSMutableData *commandToSend = [[NSMutableData alloc] init];
    long byte;
    char bytes[3] = {'\0', '\0', '\0'};
    int i;
    for (i = 0; i < [hexString length] / 2; i++) {
        bytes[0] = (char) [hexString characterAtIndex:i * 2];
        bytes[1] = (char) [hexString characterAtIndex:i * 2 + 1];
        byte = strtol(bytes, NULL, 16);
        [commandToSend appendBytes:&byte length:1];
    }
    return commandToSend;
}

- (NSString *)convertDataToString:(NSData *)data {
    const unsigned char *dataBuffer = (const unsigned char *) [data bytes];

    if (!dataBuffer) {
        return [NSString string];
    }

    NSUInteger dataLength = [data length];
    NSMutableString *hexString = [NSMutableString stringWithCapacity:(dataLength * 2)];

    for (int i = 0; i < dataLength; ++i) {
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long) dataBuffer[i]]];
    }

    return [NSString stringWithString:hexString];
}

- (id)parseParameters:(CDVInvokedUrlCommand *)command {
    NSArray *data = [command arguments];
    if (data.count == 1) {
        return [data objectAtIndex:0];
    }
    return Nil;
}

@end
