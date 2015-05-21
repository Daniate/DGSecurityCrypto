//
//  INBSecurityCryptoTests.m
//  INBSecurityCryptoTests
//
//  Created by Daniate on 15/5/18.
//  Copyright (c) 2015年 Daniate. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import <INBSecurityCrypto/INBSecurityCrypto.h>

#define kText @"近日召开的国务院常务会议鼓励电信企业提升城市宽带接入速率，降低资费水平，推出流量不清零等服务，随后，三大运营商很快公布各自提速降费方案。但网络上汹涌的“差评”吐槽方案中的一些举措诚意缺失。运营商们用“不给力”的表现，再次证明要切实深化电信行业改革，不仅要靠政府监管发力推动，还须把内在驱动的“鞭子”交给市场。梳理三大运营商的提速降费方案不难发现，尽管上有敦促下有呼声，但社会期待的全业务大规模降费并没有实现。运营商只是以“限时流量”“促销套餐”等手段来拉低单价，一些“鸡肋式”套餐甚至会让有的消费者通讯费用不降反升。这种“假摔式降费”，既反映出部分电信企业“糊弄”的态度，又暴露出当前电信市场竞争度远未达到激烈的程度。缺乏有效的市场竞争，一直是电信行业改革滞后的重要原因。在消费者眼里，不仅有些“套餐”成为吸费的“圈套”，就连宽带入户这“最后一公里”，也堵在了运营商对居民小区势力范围划分形成的“垄断”上。在行业内，几家大运营商因其传统市场优势地位难以被撼动，形成较为稳定的市场份额和收益，对消费者需求和呼声长期缺乏足够关切，也缺乏进行根本变革的内在动力。这直接导致电信市场竞争格局长期固化，运营商资费居高不下，服务和基础设施有待完善，网间技术融合仍未较好实现的尴尬局面。站在更高层面审视，提速降费不仅关系到消费者利益，更关系到“互联网＋”在经济转型升级的关键时刻能否更好地产生“乘法效应”。我国已经是世界第二大经济体，世界第一大手机拥有国，网速却排在世界80名之后，人们每到一处往往满怀渴望地询问“有没有wifi”……“惜流如金”和网速瓶颈不仅显示了消费者的窘境，也在基础服务上制约着“互联网＋”的发展。因此，提速降费深层次目的是更好地提升基础设施服务，降低社会经济运行成本，满足消费者的需求，激发社会创新创业活力。此外，提速降费也是电信企业应对未来市场竞争压力，提升企业竞争力的理性选择。去年中国手机网民已达6．5亿户，数据流量消费更增长迅猛。从长远看，电信企业放低姿态，薄利多销，是其主动适应市场需求、提高经营效益的必然选择。越早意识到、想明白这点，企业在竞争力提升上就会越主动。看来，用政府之手强化改革方向，对相关行业、企业抓监管抓考核之外，在根本上还要让市场之手挥起“鞭子”，倒逼改革措施触及深层次利益落地生根。近日召开的国务院常务会议提出将推进电信市场开放和公平竞争，年内宽带接入业务开放试点企业将增加到100家以上，这无疑将更好地让市场在资源配置中发挥决定性作用，让市场主体顺应改革大潮和竞争压力拿出更多“诚意”，更好地满足消费者需求、为经济转型发展助力。"

// 以文本形式打开PEM格式的证书，所获取到的base64字符串
#define kBase64PublicKey @"MIID5DCCAsygAwIBAgIBATALBgkqhkiG9w0BAQswdzEUMBIGA1UEAwwLRGFuaWF0\
ZUNlcnQxEDAOBgNVBAoMB0RhbmlhdGUxDzANBgNVBAgMBuS4iua1tzELMAkGA1UE\
BhMCQ04xDzANBgNVBAcMBuS4iua1tzEeMBwGCSqGSIb3DQEJARYPZGFuaWF0ZUAx\
MjYuY29tMB4XDTE1MDUxODA0MDUzN1oXDTI1MDUxNTA0MDUzN1owdzEUMBIGA1UE\
AwwLRGFuaWF0ZUNlcnQxEDAOBgNVBAoMB0RhbmlhdGUxDzANBgNVBAgMBuS4iua1\
tzELMAkGA1UEBhMCQ04xDzANBgNVBAcMBuS4iua1tzEeMBwGCSqGSIb3DQEJARYP\
ZGFuaWF0ZUAxMjYuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\
rmkRfH8qROmgDaKdhNVP/hD58Nb+w7l/yM4mbYY6XUcGnFEI44lcNem/m6qUVR+T\
2xMqeOYHdJ7SogufHNphnZsi1hljVYOoS/ZZaotTBOvio+nQE41CTNSo3h8pinNh\
Lus1vv35aXkGA4SW0ZwRc8/CrJo4ZPtkO92K+T+yIfC+57Ct12PHu1Z3q2SjFKds\
GWC5xcfBDdUcnZMONky0mTI0vJSNllAtiDqsVAtM8X7z/3vAbbGV16stg2RUAR3c\
TBEHAoG/BuW2cNEWO8F6cn0sXyAqOcYaNQGBgVxJKrICYdcZ2MX1GHbU0W7FK25D\
Xz1+d/JAWFyVO0zNHcbZCQIDAQABo30wezAPBgNVHQ8BAf8EBQMDB/+AMEwGA1Ud\
JQEB/wRCMEAGCCsGAQUFBwMEBggrBgEFBQcDAgYIKwYBBQUHAwEGCCsGAQUFBwMD\
BgcrBgEFAgMEBgcrBgEFAgMFBgRVHSUAMBoGA1UdEQQTMBGBD2RhbmlhdGVAMTI2\
LmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAhHcLDksfL6JrDPS6NuP/dIkZkU0efDGh\
MvensDjebys4OHTZ+JRUB/WrGQG9z4NULQCyUu2U19O6J//TJPnHznRwHJFuUsmz\
yrSAyRUsBv90L4g+phzQWCl3ECTwft+n/L73CJLNC+HZPZsMJSr41meOv7I7RXGY\
IgqwaDQYsl5tB7BUmVqVIHoCzndhvpTF84UJyMlOCDeaZFY85Jjfokjnz9AFDaiF\
AnWUvec39pTE48Lpw6Hv0AEoKIj9LUM9WFqX33qv6ZNcOhYnFIlXcmD2EH2fuojn\
AykJuj5Zp2mz4r8uf6yBhORuG3mIXZzUIeH1WlTDOYoxNXJxbUHjWg=="

@interface INBSecurityCryptoTests : XCTestCase
@property (nonatomic, copy) NSData *plainData;
@end

@implementation INBSecurityCryptoTests

- (void)setUp {
	[super setUp];
	// Put setup code here. This method is called before the invocation of each test method in the class.
	self.plainData = [kText dataUsingEncoding:NSUTF8StringEncoding];
	NSUInteger length = self.plainData.length;
	NSLog(@"plainText length - %lu", (unsigned long)kText.length);
	NSLog(@"plainData length - %lu", (unsigned long)length);
	NSLog(@"长度%@DES分组大小", length >= kCCBlockSizeDES ? @"不小于" : @"小于");
	NSLog(@"长度%@3DES分组大小", length >= kCCBlockSize3DES ? @"不小于" : @"小于");
	NSLog(@"长度%@AES分组大小", length >= kCCBlockSizeAES128 ? @"不小于" : @"小于");
}

- (void)tearDown {
	// Put teardown code here. This method is called after the invocation of each test method in the class.
	[super tearDown];
}

- (void)testSecurePRNG {
	u_int32_t rndLen = arc4random() % 100 + 1;
	NSData *randomData = [NSData generateSecureRandomData:rndLen];
	NSString *rndStr = [randomData encodeToHexString];
	NSLog(@"random - %@", rndStr);
	XCTAssertNotNil(randomData, @"Secure PRNG: 安全伪随机数为空");
}

- (void)testDES {
	CCAlgorithm alg = kCCAlgorithmDES;
	NSData *key = [NSData generateSymmetricKeyForAlgorithm:alg];
	NSData *iv = nil;
	if (arc4random() % 2 == 0) {
		iv = [NSData generateIVForAlgorithm:alg];
	}
	NSLog(@"iv - %@", [iv encodeToHexString]);
	BOOL isPKCS7Padding = (arc4random() % 2 == 0);
	BOOL isECB = (arc4random() % 2 == 0);
	NSLog(@"DES isPKCS7Padding - %@ isECB - %@", isPKCS7Padding ? @"YES" : @"NO", isECB ? @"YES" : @"NO");
	NSData *cipherData = [self.plainData doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCEncrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
	NSData *plainData_ = [cipherData doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCDecrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
	NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	unichar uc = [text characterAtIndex:text.length - 1];
	NSLog(@"%x", uc);
	NSLog(@"text - |%@|", text);
	XCTAssert([kText isEqualToString:[text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]], @"DES: 原始数据与解密出来的数据不一致");
}

- (void)testCAST {
	CCAlgorithm alg = kCCAlgorithmCAST;
	NSData *key = [NSData generateSymmetricKeyForAlgorithm:alg];
	NSData *iv = nil;
	if (arc4random() % 2 == 0) {
		iv = [NSData generateIVForAlgorithm:alg];
	}
	NSLog(@"iv - %@", [iv encodeToHexString]);
	BOOL isPKCS7Padding = (arc4random() % 2 == 0);
	BOOL isECB = (arc4random() % 2 == 0);
	NSLog(@"CAST isPKCS7Padding - %@ isECB - %@", isPKCS7Padding ? @"YES" : @"NO", isECB ? @"YES" : @"NO");
	NSData *cipherData = [self.plainData doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCEncrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
	NSData *plainData_ = [cipherData doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCDecrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
	NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	NSLog(@"text - |%@|", text);
	XCTAssert([kText isEqualToString:text], @"CAST: 原始数据与解密出来的数据不一致");
}

- (void)testRC2 {
	CCAlgorithm alg = kCCAlgorithmRC2;
	NSData *key = [NSData generateSymmetricKeyForAlgorithm:alg];
	NSData *iv = nil;
	if (arc4random() % 2 == 0) {
		iv = [NSData generateIVForAlgorithm:alg];
	}
	NSLog(@"iv - %@", [iv encodeToHexString]);
	BOOL isPKCS7Padding = (arc4random() % 2 == 0);
	BOOL isECB = (arc4random() % 2 == 0);
	NSLog(@"RC2 isPKCS7Padding - %@ isECB - %@", isPKCS7Padding ? @"YES" : @"NO", isECB ? @"YES" : @"NO");
	NSData *cipherData = [self.plainData doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCEncrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
	NSData *plainData_ = [cipherData doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCDecrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
	NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	NSLog(@"text - |%@|", text);
	XCTAssert([kText isEqualToString:text], @"RC2: 原始数据与解密出来的数据不一致");
}

- (void)testBlowfish {
	CCAlgorithm alg = kCCAlgorithmBlowfish;
	NSData *key = [NSData generateSymmetricKeyForAlgorithm:alg];
	NSData *iv = nil;
	if (arc4random() % 2 == 0) {
		iv = [NSData generateIVForAlgorithm:alg];
	}
	NSLog(@"iv - %@", [iv encodeToHexString]);
	BOOL isPKCS7Padding = (arc4random() % 2 == 0);
	BOOL isECB = (arc4random() % 2 == 0);
	NSLog(@"Blowfish isPKCS7Padding - %@ isECB - %@", isPKCS7Padding ? @"YES" : @"NO", isECB ? @"YES" : @"NO");
	NSData *cipherData = [self.plainData doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCEncrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
	NSData *plainData_ = [cipherData doBlockCipherWithAlgorithm:alg key:key iv:iv operation:kCCDecrypt isPKCS7Padding:isPKCS7Padding isECB:isECB];
	NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	NSLog(@"text - |%@|", text);
	XCTAssert([kText isEqualToString:text], @"Blowfish: 原始数据与解密出来的数据不一致");
}

- (void)test3DES {
	INBTripleDES *tripleDES = [INBTripleDES sharedINBTripleDES];
	NSData *cipherData = [tripleDES tripleDESEncrypt:self.plainData];
	NSData *plainData_ = [tripleDES tripleDESDecrypt:cipherData];
	NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	XCTAssert([kText isEqualToString:text], @"3DES: 原始数据与解密出来的数据不一致");
	
	// IV is NULL
	NSData *key = [NSData generateSymmetricKeyForAlgorithm:kCCAlgorithm3DES];
	cipherData = [tripleDES doCipher:self.plainData key:key iv:nil operation:kCCEncrypt];
	plainData_ = [tripleDES doCipher:cipherData key:key iv:nil operation:kCCDecrypt];
	text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	NSLog(@"text - |%@|", text);
	XCTAssert([kText isEqualToString:text], @"AES: 原始数据与解密出来的数据不一致");
}
/**
 *  AES
 */
- (void)testAES {
	INBAES *aes = [INBAES sharedINBAES];
	[aes updateKeyWithKeySize:kCCKeySizeAES256];
	[aes updateIV];
	NSLog(@"AES key - %@", [aes.key encodeToHexString]);
	NSLog(@"AES  iv - %@", [aes.iv encodeToHexString]);
	NSData *cipherData = [aes AES256Encrypt:self.plainData];
	NSData *plainData_ = [aes AES256Decrypt:cipherData];
	NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	NSLog(@"text - |%@|", text);
	XCTAssert([kText isEqualToString:text], @"AES: 原始数据与解密出来的数据不一致");
	
	// IV is NULL
	NSData *key = [NSData generateSymmetricKeyForAlgorithm:kCCAlgorithmAES];
	cipherData = [aes doCipher:self.plainData key:key iv:nil operation:kCCEncrypt];
	plainData_ = [aes doCipher:cipherData key:key iv:nil operation:kCCDecrypt];
	text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	NSLog(@"text - |%@|", text);
	XCTAssert([kText isEqualToString:text], @"AES: 原始数据与解密出来的数据不一致");
}
/**
 *  RSA
 */
- (void)testRSA {
	INBRSA *rsa = [INBRSA sharedINBRSA];
	NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"DaniateCert" ofType:@"p12"];
	XCTAssert(path, @"未能找到p12文件");
	// p12文件的密码为111111
	BOOL success = [rsa keysFromPersonalInformationExchangeFile:path password:@"111111"];
	XCTAssertTrue(success, @"未能成功获取RSA公私钥");
	NSLog(@"rsa private key - %@", rsa.privateKey);
	NSLog(@"rsa public  key - %@", rsa.publicKey);
	size_t privateBlockSize = SecKeyGetBlockSize(rsa.privateKey);
	size_t publicBlockSize = SecKeyGetBlockSize(rsa.publicKey);
	NSLog(@"分组大小: %zd %zd", privateBlockSize, publicBlockSize);
	NSData *cipherData = [rsa encryptDataWithPublicKey:self.plainData];
	NSData *plainData_ = [rsa decryptDataWithPrivateKey:cipherData];
	NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	NSLog(@"text - |%@|", text);
	XCTAssert([kText isEqualToString:text], @"RSA: 原始数据与解密出来的数据不一致");
}

- (void)testLoadPublicKeyFromCert {
	INBRSA *rsa = [INBRSA sharedINBRSA];
	SecKeyRef publicKeyOld = rsa.publicKey;
	NSLog(@"before - %@", publicKeyOld);
	NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"DaniateCert" ofType:@"cer"];
	if ([rsa publicKeyFromDERData:[NSData dataWithContentsOfFile:path]]) {
		NSLog(@"after - %@", rsa.publicKey);
	}
	XCTAssert(YES);
}

- (void)testLoadPublicKeyFromBase64CertData {
	NSData *certData = [NSData base64DecodedDataWithString:kBase64PublicKey];
	INBRSA *rsa = [INBRSA sharedINBRSA];
	SecKeyRef publicKeyOld = rsa.publicKey;
	NSLog(@"before - %@", publicKeyOld);
	if ([rsa publicKeyFromDERData:certData]) {
		NSLog(@"after - %@", rsa.publicKey);
	}
	XCTAssert(YES);
}

/**
 *  数字签名
 */
- (void)testDigitalSignature {
	INBRSA *rsa = [INBRSA sharedINBRSA];
	// 自iOS 5.0起，不再支持kSecPaddingPKCS1MD2、kSecPaddingPKCS1MD5
	NSArray *paddings = @[
//						  @(kSecPaddingPKCS1MD2),/* Unsupported as of iOS 5.0 */
//						  @(kSecPaddingPKCS1MD5),/* Unsupported as of iOS 5.0 */
						  @(kSecPaddingPKCS1SHA1),
						  @(kSecPaddingPKCS1SHA224),
						  @(kSecPaddingPKCS1SHA256),
						  @(kSecPaddingPKCS1SHA384),
						  @(kSecPaddingPKCS1SHA512),
						  ];
	NSUInteger idx = arc4random() % paddings.count;
	NSNumber *padding = paddings[idx];
	rsa.padding = padding.unsignedIntValue;
	NSLog(@"padding - %x", rsa.padding);
	NSLog(@"rsa private key - %@", rsa.privateKey);
	NSLog(@"rsa public  key - %@", rsa.publicKey);
	NSData *sigData = [rsa signDataWithPrivateKey:self.plainData];
	XCTAssert(sigData != nil, @"签名失败");
	BOOL success = [rsa verifyDataWithPublicKey:self.plainData digitalSignature:sigData];
	XCTAssert(success, @"验签失败");
}

- (void)testHex {
	NSData *hex = [self.plainData encodeToHexData];
	NSData *plainData_ = [hex decodeFromHexData];
	NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	XCTAssert([kText isEqualToString:text], @"Hex: 原始数据与解码后的数据不一致");
	
	NSString *hexStr = [kText encodeToHexString];
	NSString *originText = [hexStr decodeFromHexString];
	XCTAssert([kText isEqualToString:originText], @"Hex: 原始数据与解码后的数据不一致");
}

- (void)testBase64 {
	NSData *base64 = [self.plainData base64EncodedData];
	NSData *plainData_ = [base64 base64DecodedData];
	NSString *text = [[NSString alloc] initWithData:plainData_ encoding:NSUTF8StringEncoding];
	XCTAssert([kText isEqualToString:text], @"Base64: 原始数据与解码后的数据不一致");
}

- (void)testMD {
	NSString *md2 = [[self.plainData MD2] encodeToHexString];
	NSString *md4 = [[self.plainData MD4] encodeToHexString];
	// 可在命令行中使用md5命令，查看结果是否一致。例如，md5 -s "中华人民共和国"
	NSString *md5 = [[self.plainData MD5] encodeToHexString];
	
	NSLog(@"md2 - %@", md2);
	NSLog(@"md4 - %@", md4);
	NSLog(@"md5 - %@", md5);
	// 命令`md5 -s "中华人民共和国"`，MD5 ("中华人民共和国") = 025fceab9418be86066b60a71bc71485
	NSString *s = @"中华人民共和国";
	md5 = [[[s dataUsingEncoding:NSUTF8StringEncoding] MD5] encodeToHexString];
	NSLog(@"md5 - %@", md5);
	XCTAssert([@"025fceab9418be86066b60a71bc71485" isEqualToString:md5], @"MD5结果不一致");
}

- (void)testSHA {
	// 可在命令行中使用shasum命令，查看结果是否一致
	NSString *sha1 = [[self.plainData SHA1] encodeToHexString];
	NSString *sha224 = [[self.plainData SHA224] encodeToHexString];
	NSString *sha256 = [[self.plainData SHA256] encodeToHexString];
	NSString *sha384 = [[self.plainData SHA384] encodeToHexString];
	NSString *sha512 = [[self.plainData SHA512] encodeToHexString];
	
	// `shasum DaniateCert.cer`，结果为126686d12b27eca887acee5c55934f512e848144
	// `shasum -a 224 DaniateCert.cer`，结果为f11fd42226f3ee1bb6fe42ecd54c7b4406a62998172019fad9b2af8b
	// `shasum -a 256 DaniateCert.cer`，结果为2f9deb3bc80e4618e81b050c3108bd9a3bb39fd1dfa9f3bc08e4c1807a248088
	// `shasum -a 384 DaniateCert.cer`，结果为4b04f4d607271041576f4b8b841fe69a4fbc33a07597a20a03ed3451775852ccd980cb67b41c814f98fd2839f945581f
	// `shasum -a 512 DaniateCert.cer`，结果为df25e73786485a911b54d0c1fda229ca4b229ab51b40af8cb3e9be95ebf85844a88a8590fa8bbcf9b47a166d305379cf5d3de0b4321f63c0960f41d6957eda3e
	NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:@"DaniateCert" ofType:@"cer"];
	XCTAssert(path, @"未能找到证书文件");
	NSData *data = [NSData dataWithContentsOfFile:path];
	sha1 = [[data SHA1] encodeToHexString];
	sha224 = [[data SHA224] encodeToHexString];
	sha256 = [[data SHA256] encodeToHexString];
	sha384 = [[data SHA384] encodeToHexString];
	sha512 = [[data SHA512] encodeToHexString];
	XCTAssert([@"126686d12b27eca887acee5c55934f512e848144" isEqualToString:sha1], @"SHA1结果不一致");
	XCTAssert([@"f11fd42226f3ee1bb6fe42ecd54c7b4406a62998172019fad9b2af8b" isEqualToString:sha224], @"SHA224结果不一致");
	XCTAssert([@"2f9deb3bc80e4618e81b050c3108bd9a3bb39fd1dfa9f3bc08e4c1807a248088" isEqualToString:sha256], @"SHA256结果不一致");
	XCTAssert([@"4b04f4d607271041576f4b8b841fe69a4fbc33a07597a20a03ed3451775852ccd980cb67b41c814f98fd2839f945581f" isEqualToString:sha384], @"SHA384结果不一致");
	XCTAssert([@"df25e73786485a911b54d0c1fda229ca4b229ab51b40af8cb3e9be95ebf85844a88a8590fa8bbcf9b47a166d305379cf5d3de0b4321f63c0960f41d6957eda3e" isEqualToString:sha512], @"SHA512结果不一致");
}

- (void)testHMAC {
	CCHmacAlgorithm alg = kCCHmacAlgMD5;
	NSData *key = [NSData generateHmacKeyForAlgorithm:alg];
	NSData *hmac = [self.plainData HmacWithAlgorithm:alg key:key];
	NSString *hmacHex = [hmac encodeToHexString];
	NSLog(@"hmac md5 - %@", hmacHex);
	
	alg = kCCHmacAlgSHA1;
	key = [NSData generateHmacKeyForAlgorithm:alg];
	hmac = [self.plainData HmacWithAlgorithm:alg key:key];
	hmacHex = [hmac encodeToHexString];
	NSLog(@"hmac sha1 - %@", hmacHex);
	
	alg = kCCHmacAlgSHA224;
	key = [NSData generateHmacKeyForAlgorithm:alg];
	hmac = [self.plainData HmacWithAlgorithm:alg key:key];
	hmacHex = [hmac encodeToHexString];
	NSLog(@"hmac sha224 - %@", hmacHex);
	
	alg = kCCHmacAlgSHA256;
	key = [NSData generateHmacKeyForAlgorithm:alg];
	hmac = [self.plainData HmacWithAlgorithm:alg key:key];
	hmacHex = [hmac encodeToHexString];
	NSLog(@"hmac sha256 - %@", hmacHex);
	
	alg = kCCHmacAlgSHA384;
	key = [NSData generateHmacKeyForAlgorithm:alg];
	hmac = [self.plainData HmacWithAlgorithm:alg key:key];
	hmacHex = [hmac encodeToHexString];
	NSLog(@"hmac sha384 - %@", hmacHex);
	
	alg = kCCHmacAlgSHA512;
	key = [NSData generateHmacKeyForAlgorithm:alg];
	hmac = [self.plainData HmacWithAlgorithm:alg key:key];
	hmacHex = [hmac encodeToHexString];
	NSLog(@"hmac sha512 - %@", hmacHex);
	// 可用长度更长的密钥
	key = [NSData generateSecureRandomData:CC_SHA512_DIGEST_LENGTH << 1];
	hmac = [self.plainData HmacWithAlgorithm:alg key:key];
	hmacHex = [hmac encodeToHexString];
	NSLog(@"hmac sha512 - %@", hmacHex);
	// 可用长度更短的密钥
	key = [NSData generateSecureRandomData:arc4random() % 10 + 1];
	hmac = [self.plainData HmacWithAlgorithm:alg key:key];
	hmacHex = [hmac encodeToHexString];
	NSLog(@"hmac sha512 - %@", hmacHex);
}

@end
