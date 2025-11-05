#include <stdio.h>
//#include <string.h>
#include "cryptlib/cryptlib.h"
#include "buffer.h"

#define false 0
#define true 1
#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define DES3_KEY_SIZE 21
#define DES3_BLOCK_SIZE 8
#define MD5_BLOCK_SIZE 64
#define SHA1_BLOCK_SIZE 64
#define SHA256_BLOCK_SIZE 64
#define ARBITRARY_MAX_SIGNATURE_LEN 0x10000
//#define KEY_PASSWORD "AbCdEf16"

typedef const char* string;
typedef int bool;

int ret = CRYPT_OK;
byte bufferA[BUFFER_SIZE];
int ivSize;
byte iv[CRYPT_MAX_IVSIZE];

void handle(string location) {
    if (ret != CRYPT_OK) {
        printf("Error %d at \"%s\"\n", ret, location);
    }
}

void reset() {
    clearBuffer(bufferA);
}

int getKeyLen(CRYPT_CONTEXT context) {
    int keyLen;
    ret = cryptGetAttribute(context, CRYPT_CTXINFO_KEYSIZE, &keyLen);
    handle("Trim to key length");
    return keyLen;
}

byte toHexByte(int b) {
    if (b < 0) return '0';
    else if (b < 10) return '0' + b;
    else if (b < 16) return 'a' + b - 10;
    else return 'f';
}

void copyStringAsHex(buffer_t original, buffer_t hex, int size) { // NOLINT(*-non-const-parameter)
    for (int i = 0; i < size; i++) {
        hex[2 * i] = toHexByte(original[i] & 0x0f);
        hex[2 * i + 1] = toHexByte((original[i] & 0xf0) >> 4);
    }

}

// #############################################################################

void performAES(string inputFile, string outputFile, byte* key, bool shouldDecrypt) {
    reset();
    CRYPT_CONTEXT context;
    ret = cryptCreateContext(&context, CRYPT_UNUSED, CRYPT_ALGO_AES);
    handle("AES context creation");
    ret = cryptSetAttributeString(context, CRYPT_CTXINFO_KEY, key, AES_KEY_SIZE);
    handle("AES key setting");
    size_t bread = readFromfile(inputFile, bufferA);
    if (!shouldDecrypt) {  // Encryption
        bread = fillBufferTillDivisible(bufferA, AES_BLOCK_SIZE);
        ret = cryptEncrypt(context, bufferA, (int) bread);
        handle("AES encryption");
        ret = cryptGetAttributeString(context, CRYPT_CTXINFO_IV, iv, &ivSize);
        handle("AES IV extraction");
    } else {  // Decryption
        ret = cryptSetAttributeString(context, CRYPT_CTXINFO_IV, iv, ivSize);
        handle("AES IV setting");
        ret = cryptDecrypt(context, bufferA, (int) bread);
        handle("AES decryption");
    }
    ret = writeToFile(outputFile, bufferA);
    handle("AES file write");
    cryptDestroyContext(context);
}

void perform3DES(string inputFile, string outputFile, byte* key, bool shouldDecrypt) {
    reset();
    CRYPT_CONTEXT context;
    ret = cryptCreateContext(&context, CRYPT_UNUSED, CRYPT_ALGO_3DES);
    handle("3DES context creation");
    ret = cryptSetAttributeString(context, CRYPT_CTXINFO_KEY, key, DES3_KEY_SIZE);
    handle("3DES key setting");
    size_t bread = readFromfile(inputFile, bufferA);

    if (!shouldDecrypt) {  // Encryption
        bread = fillBufferTillDivisible(bufferA, DES3_BLOCK_SIZE);
        ret = cryptEncrypt(context, bufferA, (int) bread);
        handle("3DES encryption");
        ret = cryptGetAttributeString(context, CRYPT_CTXINFO_IV, iv, &ivSize);
        handle("3DES IV extraction");
    } else {  // Decryption
        ret = cryptSetAttributeString(context, CRYPT_CTXINFO_IV, iv, ivSize);
        handle("3DES IV setting");
        ret = cryptDecrypt(context, bufferA, (int) bread);
        handle("3DES decryption");
    }
    ret = writeToFile(outputFile, bufferA);
    handle("3DES file write");
    cryptDestroyContext(context);
}

//void performElGamal(string inputFile, string outputFile, string keyFile, string keyEmail, bool shouldDecrypt) {
//    reset();
//    CRYPT_KEYSET keyset;
//    CRYPT_CONTEXT context;
//    ret = cryptCreateContext(&context, CRYPT_UNUSED, CRYPT_ALGO_ELGAMAL);
//    handle("ElGamal context creation");
//    cryptSetAttributeString( context, CRYPT_CTXINFO_LABEL, "Key Pair", 9 );
//    ret = cryptGenerateKey(context);
//    handle("ElGamal key generation");
////    ret = cryptKeysetOpen(&keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, keyFile, CRYPT_KEYOPT_READONLY);
////    handle("ElGamal keyset init");
//    size_t bread = readFromfile(inputFile, bufferA);
//
//    if (!shouldDecrypt) {  // Encrypt
////        bread = fillBufferTillDivisible(bufferA, 256);
////        ret = cryptGetPublicKey(keyset, &context, CRYPT_KEYID_EMAIL, keyEmail);
////        handle("ElGamal public keyFile import");
//        ret = cryptEncrypt(context, bufferA, (int) bread);
//        handle("ElGamal encryption");
//    } else {  // Decrypt
////        ret = cryptGetPrivateKey(keyset, &context, CRYPT_KEYID_EMAIL, keyEmail, KEY_PASSWORD);
////        handle("ElGamal private keyFile import");
//        ret = cryptDecrypt(context, bufferA, (int) bread);
//        handle("ElGamal decryption");
//    }
//    ret = writeToFile(outputFile, bufferA);
//    handle("ElGamal file write");
//    cryptDestroyContext(context);
////    cryptKeysetClose(keyset);
//}

void generateRSAKeys(CRYPT_CONTEXT* ctxPtr) {
    ret = cryptCreateContext(ctxPtr, CRYPT_UNUSED, CRYPT_ALGO_RSA);
    handle("RSA context creation");
    cryptSetAttributeString(*ctxPtr, CRYPT_CTXINFO_LABEL, "Key Pair", 5 );
    ret = cryptGenerateKey(*ctxPtr);
    handle("RSA key generation");
}

void generateElGamalKeys(CRYPT_CONTEXT* ctxPtr) {
    ret = cryptCreateContext(ctxPtr, CRYPT_UNUSED, CRYPT_ALGO_ELGAMAL);
    handle("ElGamal context creation");
    cryptSetAttributeString(*ctxPtr, CRYPT_CTXINFO_LABEL, "Key Pair", 5 );
    ret = cryptGenerateKey(*ctxPtr);
    handle("ElGamal key generation");
}

void generateEDDSAKeys(CRYPT_CONTEXT* ctxPtr) {
    ret = cryptCreateContext(ctxPtr, CRYPT_UNUSED, CRYPT_ALGO_ELGAMAL);
    handle("EDDSA context creation");
    cryptSetAttributeString(*ctxPtr, CRYPT_CTXINFO_LABEL, "Key Pair", 5 );
    ret = cryptGenerateKey(*ctxPtr);
    handle("EDDSA key generation");
}

void performElGamalOrRSA(CRYPT_CONTEXT context, string inputFile, string outputFile, bool shouldDecrypt) {
    reset();

    readFromfile(inputFile, bufferA);
    size_t bread = trimOrPad(bufferA, getKeyLen(context));

    if (!shouldDecrypt) {  // Encrypt
        ret = cryptEncrypt(context, bufferA, (int) bread);
        handle("RSA/ElGamal encryption");
    } else {  // Decrypt
        ret = cryptDecrypt(context, bufferA, (int) bread);
        handle("RSA/ElGamal decryption");
    }
    ret = writeToFile(outputFile, bufferA);
    handle("RSA/ElGamal file write");
}

CRYPT_CONTEXT performDigest(string inputFile, CRYPT_ALGO_TYPE hashAlgo, int blockSize) {
    reset();

    CRYPT_CONTEXT context;
    ret = cryptCreateContext(&context, CRYPT_UNUSED, hashAlgo);
    handle("Digest context creation");

    readFromfile(inputFile, bufferA);
    size_t bread = fillBufferTillDivisible(bufferA, blockSize);

    for (int i = 0; i < bread; i += blockSize) {
        cryptEncrypt(context, &(bufferA[i]), blockSize);
    }
    cryptEncrypt(context, bufferA, 0);

    return context;
}

void performDigestAndPrint(string inputFile, CRYPT_ALGO_TYPE hashAlgo, int blockSize, string name) {
    byte digest[CRYPT_MAX_HASHSIZE], hex[CRYPT_MAX_HASHSIZE * 2];
    for (int i = 0; i < CRYPT_MAX_HASHSIZE * 2; i++) hex[i] = 0;
    CRYPT_CONTEXT context = performDigest(inputFile, hashAlgo, blockSize);

    int hashLen;
    ret = cryptGetAttributeString(context, CRYPT_CTXINFO_HASHVALUE, digest, &hashLen);
    handle("Digest extraction");

    copyStringAsHex(digest, hex, hashLen);
    printf("%s digest: %s\n", name, hex);
}

int performSign(CRYPT_CONTEXT signContext, string inputFile, buffer_t signature) {
    reset();
    int signLen;
    CRYPT_CONTEXT hashContext = performDigest(inputFile, CRYPT_ALGO_SHA2, SHA256_BLOCK_SIZE);
    ret = cryptCreateSignature(signature, ARBITRARY_MAX_SIGNATURE_LEN, &signLen, signContext, hashContext);
    handle("Signature generation");
    cryptDestroyContext(hashContext);
    return signLen;
}

bool verifySignature(CRYPT_CONTEXT signContext, string inputFile, buffer_t signature, int signLen) {
//    CRYPT_CONTEXT hashContext = performDigest(inputFile, CRYPT_ALGO_MD5, MD5_BLOCK_SIZE);  // <- uncomment for incorrect signature
    CRYPT_CONTEXT hashContext = performDigest(inputFile, CRYPT_ALGO_SHA2, SHA256_BLOCK_SIZE);
    ret = cryptCheckSignature(signature, signLen, signContext, hashContext);
    if (ret != CRYPT_ERROR_SIGNATURE) handle("Signature check");
    cryptDestroyContext(hashContext);
    return ret != CRYPT_ERROR_SIGNATURE;
}

// #############################################################################

void beforeMain() {
    ret = cryptInit();
    handle("Cryptlib init");
}

void afterMain() {
    cryptEnd();
}

void fullAES() {
    buffer_t aesKey = (buffer_t) "aaaabbbbccccdddd";
    performAES("resources/raccoon.jpg", "resources/aes/cypher.out", aesKey, false);
    performAES("resources/aes/cypher.out", "resources/aes/decoded.jpg", aesKey, true);
}

void full3DES() {
    buffer_t des3Key = (buffer_t) "aaabbbcccdddeeefffggg";
    perform3DES("resources/raccoon.jpg", "resources/3des/cypher.out", des3Key, false);
    perform3DES("resources/3des/cypher.out", "resources/3des/decoded.jpg", des3Key, true);
}

void fullElGamal() {
    CRYPT_CONTEXT context;
    generateElGamalKeys(&context);
    performElGamalOrRSA(
            context,
            "resources/plain1.txt",
            "resources/elgamal/cypher.out",
            false
    );
    performElGamalOrRSA(
            context,
            "resources/elgamal/cypher.out",
            "resources/elgamal/decoded.txt",
            true
    );

    cryptDestroyContext(context);
}

void fullRSA() {
    CRYPT_CONTEXT context;
    generateRSAKeys(&context);
    performElGamalOrRSA(
            context,
            "resources/plain1.txt",
            "resources/rsa/cypher.out",
            false
            );
    performElGamalOrRSA(
            context,
            "resources/rsa/cypher.out",
            "resources/rsa/decoded.txt",
            true
    );

    cryptDestroyContext(context);
}

void fullSignature() {
    CRYPT_CONTEXT signContext;
    byte signature[ARBITRARY_MAX_SIGNATURE_LEN];
    generateRSAKeys(&signContext);
    int signLen = performSign(signContext, "resources/raccoon.jpg", signature);
    bool check = verifySignature(signContext, "resources/raccoon.jpg", signature, signLen);
    printf("File signature %s\n", check ? "correct" : "incorrect");
    cryptDestroyContext(signContext);
}

int main() {
    beforeMain();

    fullAES();
    full3DES();

//    fullElGamal();  // <-- does not work (refer to manual page 200)
    fullRSA();

    performDigestAndPrint("resources/raccoon.jpg", CRYPT_ALGO_MD5, MD5_BLOCK_SIZE, "MD5");
    performDigestAndPrint("resources/raccoon.jpg", CRYPT_ALGO_SHA1, SHA1_BLOCK_SIZE, "SHA-1");
    performDigestAndPrint("resources/raccoon.jpg", CRYPT_ALGO_SHA2, SHA256_BLOCK_SIZE, "SHA-256");

    fullSignature();

    afterMain();
    return 0;
}
