#import "CSRModule.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

static NSString * const DEFAULT_COUNTRY = @"US";
static NSString * const DEFAULT_STATE = @"Colorado";
static NSString * const DEFAULT_LOCALITY = @"Denver";
static NSString * const DEFAULT_ORGANIZATION = @"MyOrg";
static NSString * const DEFAULT_ORGANIZATIONAL_UNIT = @"MyOrgUnit";
static NSString * const DEFAULT_IP_ADDRESS = @"10.10.10.10";
static NSString * const DEFAULT_ECC_CURVE = @"secp384r1";

@implementation CSRModule

RCT_EXPORT_MODULE(CSRModule)

// Export the generateCSR method to JavaScript
RCT_EXPORT_METHOD(generateCSR:(NSDictionary *)params
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        // Extract parameters from params
        NSString *commonName = params[@"commonName"] ?: @"";
        NSString *serialNumber = params[@"serialNumber"] ?: @"";
        NSString *country = params[@"country"] ?: DEFAULT_COUNTRY;
        NSString *state = params[@"state"] ?: DEFAULT_STATE;
        NSString *locality = params[@"locality"] ?: DEFAULT_LOCALITY;
        NSString *organization = params[@"organization"] ?: DEFAULT_ORGANIZATION;
        NSString *organizationalUnit = params[@"organizationalUnit"] ?: DEFAULT_ORGANIZATIONAL_UNIT;
        NSString *ipAddress = params[@"ipAddress"] ?: DEFAULT_IP_ADDRESS;
        NSString *dnsName = params[@"dnsName"];
        NSString *curve = params[@"curve"] ?: DEFAULT_ECC_CURVE;
        NSString *phoneInfo = params[@"phoneInfo"]; 
        NSString *privateKeyAlias = params[@"privateKeyAlias"];
        
        // Validate required parameters
        if (commonName.length == 0) {
            reject(@"INVALID_PARAM", @"commonName is required", nil);
            return;
        }
        
        if (!privateKeyAlias || privateKeyAlias.length == 0) {
            reject(@"INVALID_PARAM", @"privateKeyAlias is required", nil);
            return;
        }
        
        // Map curve names from secp* to P-* format
        NSString *normalizedCurve = [self normalizeCurveName:curve];
        
        // Generate ECC key pair with the privateKeyAlias as tag
        NSError *error = nil;
        NSDictionary *keyPair = [self generateECKeyPairForCurve:normalizedCurve 
                                                        withAlias:privateKeyAlias 
                                                            error:&error];
        if (error) {
            reject(@"KEY_GENERATION_ERROR", error.localizedDescription, error);
            return;
        }
        
        SecKeyRef privateKey = (__bridge SecKeyRef)keyPair[@"privateKey"];
        SecKeyRef publicKey = (__bridge SecKeyRef)keyPair[@"publicKey"];
        BOOL isHardwareBacked = [keyPair[@"isHardwareBacked"] boolValue];
        
        // Get public key data
        NSData *publicKeyData = [self exportPublicKey:publicKey error:&error];
        if (error) {
            reject(@"PUBLIC_KEY_ERROR", error.localizedDescription, error);
            return;
        }
        
        // Build CSR with phoneInfo parameter
        NSData *csrData = [self buildCSRWithSubject:@{
            @"CN": commonName,
            @"serialNumber": serialNumber,
            @"C": country,
            @"ST": state,
            @"L": locality,
            @"O": organization,
            @"OU": organizationalUnit
        }
                                          publicKey:publicKey
                                         privateKey:privateKey
                                              curve:normalizedCurve
                                          ipAddress:ipAddress
                                          dnsName:dnsName
                                          phoneInfo:phoneInfo 
                                              error:&error];
        
        if (error) {
            reject(@"CSR_GENERATION_ERROR", error.localizedDescription, error);
            return;
        }
        
        // Convert to PEM format
        NSString *csrPEM = [self convertToPEM:csrData label:@"CERTIFICATE REQUEST"];
        NSString *publicKeyPEM = [self convertToPEM:publicKeyData label:@"PUBLIC KEY"];
        
        // Return result matching Android API
        resolve(@{
            @"csr": csrPEM,
            @"privateKeyAlias": privateKeyAlias,  // Return the alias, not the key
            @"publicKey": publicKeyPEM,
            @"isHardwareBacked": @(isHardwareBacked)
        });
        
    } @catch (NSException *exception) {
        reject(@"EXCEPTION", exception.reason, nil);
    }
}

RCT_EXPORT_METHOD(deleteKey:(NSString *)privateKeyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        BOOL success = [self deleteKeyWithAlias:privateKeyAlias];
        resolve(@(success));
    } @catch (NSException *exception) {
        reject(@"DELETE_KEY_ERROR", exception.reason, nil);
    }
}

RCT_EXPORT_METHOD(keyExists:(NSString *)privateKeyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        BOOL exists = [self keyExistsWithAlias:privateKeyAlias];
        resolve(@(exists));
    } @catch (NSException *exception) {
        reject(@"KEY_EXISTS_ERROR", exception.reason, nil);
    }
}

RCT_EXPORT_METHOD(getPublicKey:(NSString *)privateKeyAlias
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        NSError *error = nil;
        NSString *publicKeyPEM = [self getPublicKeyForAlias:privateKeyAlias error:&error];
        
        if (error) {
            reject(@"GET_PUBLIC_KEY_ERROR", error.localizedDescription, error);
            return;
        }
        
        resolve(publicKeyPEM);
    } @catch (NSException *exception) {
        reject(@"GET_PUBLIC_KEY_ERROR", exception.reason, nil);
    }
}

#pragma mark - Helper Methods

- (NSString *)normalizeCurveName:(NSString *)curveName {
    // Map secp* names to P-* format
    if ([curveName isEqualToString:@"secp256r1"]) {
        return @"P-256";
    } else if ([curveName isEqualToString:@"secp384r1"]) {
        return @"P-384";
    } else if ([curveName isEqualToString:@"secp521r1"]) {
        return @"P-521";
    }
    // Default to P-384 if unknown
    return @"P-384";
}

- (BOOL)isKeyHardwareBacked:(SecKeyRef)key {
    if (key == NULL) {
        return NO;
    }
    
    // Check if key is in Secure Enclave
    NSDictionary *attributes = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(key);
    NSString *tokenID = attributes[(id)kSecAttrTokenID];
    
    return [tokenID isEqualToString:(NSString *)kSecAttrTokenIDSecureEnclave];
}

- (BOOL)deleteKeyWithAlias:(NSString *)alias {
    NSData *tag = [alias dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
    };
    
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    return status == errSecSuccess || status == errSecItemNotFound;
}

- (BOOL)keyExistsWithAlias:(NSString *)alias {
    NSData *tag = [alias dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecReturnRef: @YES,
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (result) {
        CFRelease(result);
    }
    
    return status == errSecSuccess;
}

- (NSString *)getPublicKeyForAlias:(NSString *)alias error:(NSError **)error {
    NSData *tag = [alias dataUsingEncoding:NSUTF8StringEncoding];
    
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecReturnRef: @YES,
    };
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:@"CSRModule" 
                                         code:status 
                                     userInfo:@{NSLocalizedDescriptionKey: @"Key not found"}];
        }
        return nil;
    }
    
    SecKeyRef privateKey = (SecKeyRef)result;
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    CFRelease(result);
    
    if (!publicKey) {
        if (error) {
            *error = [NSError errorWithDomain:@"CSRModule" 
                                         code:-1 
                                     userInfo:@{NSLocalizedDescriptionKey: @"Could not extract public key"}];
        }
        return nil;
    }
    
    NSData *publicKeyData = [self exportPublicKey:publicKey error:error];
    CFRelease(publicKey);
    
    if (!publicKeyData) {
        return nil;
    }
    
    return [self convertToPEM:publicKeyData label:@"PUBLIC KEY"];
}

#pragma mark - Key Generation

- (NSDictionary *)generateECKeyPairForCurve:(NSString *)curveName 
                                  withAlias:(NSString *)alias 
                                      error:(NSError **)error {
    // Map curve names to key sizes
    int keySize = 384; // Default P-384
    if ([curveName isEqualToString:@"P-256"]) {
        keySize = 256;
    } else if ([curveName isEqualToString:@"P-521"]) {
        keySize = 521;
    }
    
    // Use the alias as the keychain tag
    NSData *tagData = [alias dataUsingEncoding:NSUTF8StringEncoding];
    
    BOOL isHardwareBacked = NO;
    SecKeyRef privateKey = NULL;
    
    // IMPORTANT: Secure Enclave only supports P-256 on iOS
    // For P-256, try Secure Enclave first, then fall back to software
    // For P-384 and P-521, use software directly
    
    if (keySize == 256) {
        // Try Secure Enclave for P-256
        NSDictionary *secureEnclaveParams = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @(keySize),
            (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,  // Use Secure Enclave
            (id)kSecPrivateKeyAttrs: @{
                (id)kSecAttrIsPermanent: @YES,
                (id)kSecAttrApplicationTag: tagData,
            }
        };
        
        CFErrorRef cfError = NULL;
        privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)secureEnclaveParams, &cfError);
        
        if (privateKey != NULL) {
            // Successfully created in Secure Enclave
            isHardwareBacked = YES;
            NSLog(@"✅ Key created in Secure Enclave (hardware-backed)");
        } else {
            // Secure Enclave failed, fall back to software
            NSLog(@"⚠️ Secure Enclave failed: %@", (__bridge NSError *)cfError);
            NSLog(@"Falling back to software key generation...");
            
            if (cfError) {
                CFRelease(cfError);
                cfError = NULL;
            }
        }
    }
    
    // If Secure Enclave failed or not P-256, create software key
    if (privateKey == NULL) {
        NSDictionary *softwareParams = @{
            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits: @(keySize),
            // NO kSecAttrTokenID - creates software key
            (id)kSecPrivateKeyAttrs: @{
                (id)kSecAttrIsPermanent: @YES,
                (id)kSecAttrApplicationTag: tagData,
            }
        };
        
        CFErrorRef cfError = NULL;
        privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)softwareParams, &cfError);
        
        if (cfError) {
            if (error) {
                *error = (__bridge_transfer NSError *)cfError;
            }
            return nil;
        }
        
        isHardwareBacked = NO;
        if (keySize == 256) {
            NSLog(@"ℹ️ Key created in software (Secure Enclave fallback)");
        } else {
            NSLog(@"ℹ️ Key created in software (P-%d does not support Secure Enclave)", keySize);
        }
    }
    
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    
    return @{
        @"privateKey": (__bridge_transfer id)privateKey,
        @"publicKey": (__bridge_transfer id)publicKey,
        @"isHardwareBacked": @(isHardwareBacked)
    };
}

- (NSData *)exportPublicKey:(SecKeyRef)publicKey error:(NSError **)error {
    CFErrorRef cfError = NULL;
    NSData *keyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(publicKey, &cfError);
    
    if (cfError) {
        if (error) {
            *error = (__bridge_transfer NSError *)cfError;
        }
        return nil;
    }
    
    // Wrap in SubjectPublicKeyInfo structure
    NSData *spki = [self wrapPublicKeyInSPKI:keyData curve:[self getCurveFromKey:publicKey]];
    return spki;
}

- (NSString *)getCurveFromKey:(SecKeyRef)key {
    NSDictionary *attributes = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(key);
    NSNumber *keySize = attributes[(id)kSecAttrKeySizeInBits];
    
    if ([keySize intValue] == 256) return @"P-256";
    if ([keySize intValue] == 384) return @"P-384";
    if ([keySize intValue] == 521) return @"P-521";
    
    return @"P-384";
}

#pragma mark - CSR Building

- (NSData *)buildCSRWithSubject:(NSDictionary *)subject
                      publicKey:(SecKeyRef)publicKey
                     privateKey:(SecKeyRef)privateKey
                          curve:(NSString *)curve
                      ipAddress:(NSString *)ipAddress
                      dnsName:(NSString *)dnsName
                      phoneInfo:(NSString *)phoneInfo 
                          error:(NSError **)error {
    
    // Build the CSR components
    NSData *subjectDN = [self encodeDN:subject];
    NSData *publicKeyInfo = [self exportPublicKey:publicKey error:error];
    if (*error) return nil;
    
    NSData *extensions = [self buildExtensions:ipAddress dnsName:dnsName phoneInfo:phoneInfo];
    NSData *attributes = [self buildAttributes:extensions];
    
    // Build CertificationRequestInfo
    NSData *certRequestInfo = [self buildCertificationRequestInfo:subjectDN
                                                       publicKeyInfo:publicKeyInfo
                                                          attributes:attributes];
    
    // Sign the CertificationRequestInfo
    NSData *signature = [self signData:certRequestInfo withPrivateKey:privateKey error:error];
    if (*error) return nil;
    
    // Build final CSR
    NSData *csr = [self buildFinalCSR:certRequestInfo signature:signature curve:curve];
    
    return csr;
}

- (NSData *)buildCertificationRequestInfo:(NSData *)subject
                            publicKeyInfo:(NSData *)publicKeyInfo
                               attributes:(NSData *)attributes {
    NSMutableData *certRequestInfo = [NSMutableData data];
    
    // Version (INTEGER 0)
    NSData *version = [self encodeInteger:0];
    
    // Combine all components
    [certRequestInfo appendData:version];
    [certRequestInfo appendData:subject];
    [certRequestInfo appendData:publicKeyInfo];
    [certRequestInfo appendData:attributes];
    
    // Wrap in SEQUENCE
    return [self wrapInSequence:certRequestInfo];
}

- (NSData *)buildFinalCSR:(NSData *)certRequestInfo
                signature:(NSData *)signature
                    curve:(NSString *)curve {
    NSMutableData *csr = [NSMutableData data];
    
    // Add CertificationRequestInfo
    [csr appendData:certRequestInfo];
    
    // Add SignatureAlgorithm (ecdsa-with-SHA256)
    NSData *signatureAlgorithm = [self encodeSignatureAlgorithm];
    [csr appendData:signatureAlgorithm];
    
    // Add Signature (BIT STRING)
    NSData *signatureBitString = [self encodeBitString:signature];
    [csr appendData:signatureBitString];
    
    // Wrap entire CSR in SEQUENCE
    return [self wrapInSequence:csr];
}

#pragma mark - DN Encoding

- (NSData *)encodeDN:(NSDictionary *)subject {
    NSMutableData *dn = [NSMutableData data];
    
    // Order matters for DN: C, ST, L, O, OU, CN, serialNumber
    NSArray *order = @[@"C", @"ST", @"L", @"O", @"OU", @"CN", @"serialNumber"];
    
    for (NSString *key in order) {
        NSString *value = subject[key];
        if (value && value.length > 0) {
            NSData *rdn = [self encodeRDN:key value:value];
            [dn appendData:rdn];
        }
    }
    
    return [self wrapInSequence:dn];
}

- (NSData *)encodeRDN:(NSString *)key value:(NSString *)value {
    // Get OID for attribute
    NSData *oid = [self getOIDForAttribute:key];
    
    // Country (C) and serialNumber use PrintableString (0x13)
    // All other fields use UTF8String (0x0C)
    NSData *stringValue;
    
    if ([key isEqualToString:@"C"] || [key isEqualToString:@"serialNumber"]) {
        stringValue = [self encodePrintableString:value];
    } else {
        stringValue = [self encodeUTF8String:value];
    }
    
    // AttributeTypeAndValue = SEQUENCE { type OID, value ANY }
    NSMutableData *atav = [NSMutableData data];
    [atav appendData:oid];
    [atav appendData:stringValue];
    NSData *atavSeq = [self wrapInSequence:atav];
    
    // RDN = SET OF AttributeTypeAndValue
    return [self wrapInSet:atavSeq];
}

- (NSData *)getOIDForAttribute:(NSString *)attribute {
    NSDictionary *oidMap = @{
        @"C": @"2.5.4.6",           // countryName
        @"ST": @"2.5.4.8",          // stateOrProvinceName
        @"L": @"2.5.4.7",           // localityName
        @"O": @"2.5.4.10",          // organizationName
        @"OU": @"2.5.4.11",         // organizationalUnitName
        @"CN": @"2.5.4.3",          // commonName
        @"serialNumber": @"2.5.4.5" // serialNumber
    };
    
    return [self encodeOID:oidMap[attribute]];
}

#pragma mark - Extensions

- (NSData *)buildExtensions:(NSString *)ipAddress dnsName:(NSString *)dnsName phoneInfo:(NSString *)phoneInfo {
    NSMutableData *extensions = [NSMutableData data];
    
    // Key Usage extension (critical)
    NSData *keyUsage = [self buildKeyUsageExtension];
    [extensions appendData:keyUsage];
    
    // Extended Key Usage extension
    NSData *extKeyUsage = [self buildExtendedKeyUsageExtension];
    [extensions appendData:extKeyUsage];
    
    // Subject Alternative Name extension (if IP or phoneInfo provided)
    if ((ipAddress && ipAddress.length > 0) || (dnsName && dnsName.length > 0) || (phoneInfo && phoneInfo.length > 0)) {
        NSData *san = [self buildSubjectAltNameExtension:ipAddress dnsName:dnsName phoneInfo:phoneInfo];
        [extensions appendData:san];
    }
    
    return [self wrapInSequence:extensions];
}

- (NSData *)buildKeyUsageExtension {
    // KeyUsage: digitalSignature (bit 0), keyAgreement (bit 4)
    // Bit positions (from left/MSB):
    //   Bit 0: digitalSignature = 10000000 = 0x80
    //   Bit 4: keyAgreement     = 00001000 = 0x08
    //   Combined:                 10001000 = 0x88
    //
    // RITICAL: DER BIT STRING format: [unused_bits, data_bytes...]
    // Since we only use bits 0 and 4 (5 bits total), we have 3 unused bits
    // Android uses: 03 02 03 88 (3 unused bits)
    // We must match this exactly!
    
    unsigned char bitStringValue[] = {0x03, 0x88}; // 3 unused bits, bits 10001000
    
    // Properly encode as BIT STRING
    NSMutableData *encodedBitString = [NSMutableData data];
    unsigned char tag = 0x03; // BIT STRING tag
    unsigned char length = 0x02; // Length is 2 bytes
    [encodedBitString appendBytes:&tag length:1];
    [encodedBitString appendBytes:&length length:1];
    [encodedBitString appendBytes:bitStringValue length:2];
    
    return [self buildExtension:@"2.5.29.15" critical:YES value:encodedBitString];
}

- (NSData *)buildExtendedKeyUsageExtension {
    // ExtKeyUsage: TLS Web Client Authentication (1.3.6.1.5.5.7.3.2)
    NSData *clientAuthOID = [self encodeOID:@"1.3.6.1.5.5.7.3.2"];
    NSData *sequence = [self wrapInSequence:clientAuthOID];
    
    return [self buildExtension:@"2.5.29.37" critical:NO value:sequence];
}


- (NSData *)buildSubjectAltNameExtension:(NSString *)ipAddress dnsName:(NSString *)dnsName phoneInfo:(NSString *)phoneInfo {
    NSMutableData *sanData = [NSMutableData data];

    // Add DNS Name(s) if provided
    if (dnsName && dnsName.length > 0) {
        @try {
            // Support multiple DNS names separated by commas
            NSArray *dnsNames = [dnsName componentsSeparatedByString:@","];
            
            for (NSString *dns in dnsNames) {
                NSString *trimmedDns = [dns stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                
                if (trimmedDns.length > 0) {
                    // Encode as UTF8
                    NSData *dnsData = [trimmedDns dataUsingEncoding:NSUTF8StringEncoding];
                    
                    // Build DNS name (CONTEXT SPECIFIC [2])
                    NSMutableData *dnsTag = [NSMutableData data];
                    unsigned char tag = 0x82; // CONTEXT [2] - dNSName
                    
                    // Encode length
                    NSData *lengthData = [self encodeLength:dnsData.length];
                    
                    [dnsTag appendBytes:&tag length:1];
                    [dnsTag appendData:lengthData];
                    [dnsTag appendData:dnsData];
                    
                    [sanData appendData:dnsTag];
                    
                    NSLog(@"✅ Added DNS name to SAN: %@", trimmedDns);
                }
            }
        } @catch (NSException *exception) {
            NSLog(@"⚠️ Failed to add DNS name to SAN: %@", exception.reason);
            // Continue without DNS rather than failing the entire CSR
        }
    }
    
    // Add IP Address if provided
    if (ipAddress && ipAddress.length > 0) {
        // Parse IP address
        NSArray *octets = [ipAddress componentsSeparatedByString:@"."];
        if (octets.count == 4) {
            // Build IP address (CONTEXT SPECIFIC [7])
            unsigned char ipBytes[4];
            for (int i = 0; i < 4; i++) {
                ipBytes[i] = (unsigned char)[octets[i] intValue];
            }
            
            NSMutableData *ipTag = [NSMutableData data];
            unsigned char tag = 0x87; // CONTEXT [7] - iPAddress
            unsigned char length = 0x04;
            [ipTag appendBytes:&tag length:1];
            [ipTag appendBytes:&length length:1];
            [ipTag appendBytes:ipBytes length:4];
            
            [sanData appendData:ipTag];
        }
    }
    
    if (phoneInfo && phoneInfo.length > 0) {
        @try {
            // Trim whitespace
            NSString *trimmedPhoneInfo = [phoneInfo stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            
            if (trimmedPhoneInfo.length > 0) {
                // Use URI format: phone:value (matching Android implementation)
                NSString *uriValue = [NSString stringWithFormat:@"phone:%@", trimmedPhoneInfo];
                
                // Encode as UTF8
                NSData *uriData = [uriValue dataUsingEncoding:NSUTF8StringEncoding];
                
                // Build URI (CONTEXT SPECIFIC [6])
                NSMutableData *uriTag = [NSMutableData data];
                unsigned char tag = 0x86; // CONTEXT [6] - uniformResourceIdentifier
                
                // Encode length
                NSData *lengthData = [self encodeLength:uriData.length];
                
                [uriTag appendBytes:&tag length:1];
                [uriTag appendData:lengthData];
                [uriTag appendData:uriData];
                
                [sanData appendData:uriTag];
                
                NSLog(@"✅ Successfully added phoneInfo as URI: %@", uriValue);
            }
        } @catch (NSException *exception) {
            NSLog(@"⚠️ Failed to add phone info to SAN: %@", exception.reason);
            // Continue without phone info rather than failing the entire CSR
        }
    }
    
    NSData *sanSequence = [self wrapInSequence:sanData];
    
    return [self buildExtension:@"2.5.29.17" critical:NO value:sanSequence];
}

- (NSData *)buildExtension:(NSString *)oidString critical:(BOOL)critical value:(NSData *)value {
    NSMutableData *extension = [NSMutableData data];
    
    // Extension OID
    [extension appendData:[self encodeOID:oidString]];
    
    // Critical flag (if true)
    if (critical) {
        NSData *criticalBool = [NSData dataWithBytes:(unsigned char[]){0x01, 0x01, 0xFF} length:3];
        [extension appendData:criticalBool];
    }
    
    // Extension value (OCTET STRING)
    [extension appendData:[self encodeOctetString:value]];
    
    return [self wrapInSequence:extension];
}

- (NSData *)buildAttributes:(NSData *)extensions {
    // Attributes = CONTEXT SPECIFIC [0]
    // Contains extensionRequest attribute
    
    // Extension Request OID: 1.2.840.113549.1.9.14
    NSData *extReqOID = [self encodeOID:@"1.2.840.113549.1.9.14"];
    
    // Wrap extensions in SET
    NSData *extSet = [self wrapInSet:extensions];
    
    // Build attribute SEQUENCE
    NSMutableData *attribute = [NSMutableData data];
    [attribute appendData:extReqOID];
    [attribute appendData:extSet];
    NSData *attrSeq = [self wrapInSequence:attribute];
    
    // Wrap in CONTEXT SPECIFIC [0]
    return [self wrapInContext:attrSeq tag:0];
}

#pragma mark - Signing

// The bug was double-hashing: manually hashing with SHA-256, then using
// kSecKeyAlgorithmECDSASignatureMessageX962SHA256 which also hashes.
// Solution: Use kSecKeyAlgorithmECDSASignatureDigestX962SHA256 which expects pre-hashed data.
- (NSData *)signData:(NSData *)data withPrivateKey:(SecKeyRef)privateKey error:(NSError **)error {
    // Hash the data with SHA-256
    NSMutableData *hash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash.mutableBytes);
    
    // Sign the hash using DigestX962SHA256 which expects pre-hashed data
    // This prevents double-hashing that was causing signature verification to fail
    CFErrorRef cfError = NULL;
    NSData *signature = (__bridge_transfer NSData *)SecKeyCreateSignature(
        privateKey,
        kSecKeyAlgorithmECDSASignatureDigestX962SHA256,  // ✅ Changed from MessageX962SHA256 to DigestX962SHA256
        (__bridge CFDataRef)hash,
        &cfError
    );
    
    if (cfError) {
        if (error) {
            *error = (__bridge_transfer NSError *)cfError;
        }
        return nil;
    }
    
    return signature;
}

- (NSData *)encodeSignatureAlgorithm {
    // ecdsa-with-SHA256 OID: 1.2.840.10045.4.3.2
    NSData *oid = [self encodeOID:@"1.2.840.10045.4.3.2"];
    return [self wrapInSequence:oid];
}

#pragma mark - Public Key Info

- (NSData *)wrapPublicKeyInSPKI:(NSData *)publicKeyData curve:(NSString *)curve {
    NSMutableData *spki = [NSMutableData data];
    
    // Algorithm Identifier
    NSData *algorithm = [self encodeAlgorithmIdentifier:curve];
    [spki appendData:algorithm];
    
    // Public Key (BIT STRING)
    NSData *publicKeyBitString = [self encodeBitString:publicKeyData];
    [spki appendData:publicKeyBitString];
    
    return [self wrapInSequence:spki];
}

- (NSData *)encodeAlgorithmIdentifier:(NSString *)curve {
    NSMutableData *algId = [NSMutableData data];
    
    // ECC Public Key OID: 1.2.840.10045.2.1
    NSData *eccOID = [self encodeOID:@"1.2.840.10045.2.1"];
    [algId appendData:eccOID];
    
    // Curve OID
    NSString *curveOID = @"1.2.840.10045.3.1.7"; // Default P-256
    if ([curve isEqualToString:@"P-384"]) {
        curveOID = @"1.3.132.0.34"; // secp384r1
    } else if ([curve isEqualToString:@"P-521"]) {
        curveOID = @"1.3.132.0.35"; // secp521r1
    }
    
    NSData *curveOIDData = [self encodeOID:curveOID];
    [algId appendData:curveOIDData];
    
    return [self wrapInSequence:algId];
}

#pragma mark - ASN.1 Encoding Primitives

- (NSData *)encodeInteger:(NSInteger)value {
    NSMutableData *data = [NSMutableData data];
    unsigned char tag = 0x02; // INTEGER
    unsigned char length = 0x01;
    unsigned char val = (unsigned char)value;
    
    [data appendBytes:&tag length:1];
    [data appendBytes:&length length:1];
    [data appendBytes:&val length:1];
    
    return data;
}

- (NSData *)encodeOID:(NSString *)oidString {
    NSArray *components = [oidString componentsSeparatedByString:@"."];
    NSMutableData *oidData = [NSMutableData data];
    
    // First two components are encoded as 40*first + second
    unsigned char firstByte = [components[0] intValue] * 40 + [components[1] intValue];
    [oidData appendBytes:&firstByte length:1];
    
    // Remaining components
    for (NSInteger i = 2; i < components.count; i++) {
        NSInteger value = [components[i] integerValue];
        NSData *encoded = [self encodeOIDComponent:value];
        [oidData appendData:encoded];
    }
    
    // Add tag and length
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x06; // OID
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:oidData.length]];
    [result appendData:oidData];
    
    return result;
}

- (NSData *)encodeOIDComponent:(NSInteger)value {
    NSMutableData *data = [NSMutableData data];
    
    if (value < 128) {
        unsigned char byte = (unsigned char)value;
        [data appendBytes:&byte length:1];
    } else {
        // Encode in base 128
        NSMutableArray *bytes = [NSMutableArray array];
        while (value > 0) {
            [bytes insertObject:@(value & 0x7F) atIndex:0];
            value >>= 7;
        }
        
        for (NSInteger i = 0; i < bytes.count; i++) {
            unsigned char byte = [bytes[i] unsignedCharValue];
            if (i < bytes.count - 1) {
                byte |= 0x80; // Set continuation bit
            }
            [data appendBytes:&byte length:1];
        }
    }
    
    return data;
}

// Match Android's exact encoding
// Country (C) and serialNumber use PrintableString (0x13)
// All other DN fields (ST, L, O, OU, CN) use UTF8String (0x0C)
- (NSData *)encodePrintableString:(NSString *)string {
    // Convert string to ASCII data (PrintableString uses ASCII subset)
    NSData *stringData = [string dataUsingEncoding:NSASCIIStringEncoding];
    NSMutableData *result = [NSMutableData data];
    
    unsigned char tag = 0x13; // PrintableString tag (NOT 0x0C UTF8String)
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:stringData.length]];
    [result appendData:stringData];
    
    return result;
}

- (NSData *)encodeUTF8String:(NSString *)string {
    NSData *stringData = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *result = [NSMutableData data];
    
    unsigned char tag = 0x0C; // UTF8String
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:stringData.length]];
    [result appendData:stringData];
    
    return result;
}

- (NSData *)encodeOctetString:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x04; // OCTET STRING
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)encodeBitString:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x03; // BIT STRING
    unsigned char unusedBits = 0x00;
    
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length + 1]];
    [result appendBytes:&unusedBits length:1];
    [result appendData:data];
    
    return result;
}

- (NSData *)wrapInSequence:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x30; // SEQUENCE
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)wrapInSet:(NSData *)data {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0x31; // SET
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)wrapInContext:(NSData *)data tag:(unsigned char)contextTag {
    NSMutableData *result = [NSMutableData data];
    unsigned char tag = 0xA0 | contextTag; // CONTEXT SPECIFIC
    [result appendBytes:&tag length:1];
    [result appendData:[self encodeLength:data.length]];
    [result appendData:data];
    return result;
}

- (NSData *)encodeLength:(NSUInteger)length {
    NSMutableData *result = [NSMutableData data];
    
    if (length < 128) {
        unsigned char byte = (unsigned char)length;
        [result appendBytes:&byte length:1];
    } else {
        // Long form
        NSMutableArray *bytes = [NSMutableArray array];
        NSUInteger temp = length;
        while (temp > 0) {
            [bytes insertObject:@(temp & 0xFF) atIndex:0];
            temp >>= 8;
        }
        
        unsigned char firstByte = 0x80 | bytes.count;
        [result appendBytes:&firstByte length:1];
        
        for (NSNumber *byte in bytes) {
            unsigned char b = [byte unsignedCharValue];
            [result appendBytes:&b length:1];
        }
    }
    
    return result;
}

#pragma mark - PEM Conversion

- (NSString *)convertToPEM:(NSData *)data label:(NSString *)label {
    NSString *base64 = [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    // Remove \r characters to match standard Unix-style line endings
    base64 = [base64 stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    
    return [NSString stringWithFormat:@"-----BEGIN %@-----\n%@\n-----END %@-----",
            label, base64, label];
}

@end
