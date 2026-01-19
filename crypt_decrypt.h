#pragma once
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>




namespace AESGCM {
    static constexpr int SALT_LEN = 16;
    static constexpr int IV_LEN = 12;
    static constexpr int TAG_LEN = 16;
    static constexpr int KEY_LEN = 32;
    static constexpr int PBKDF2_ITER = 100000;
    static constexpr int BUFFER_SIZE = 4096;

    static void print_openssl_error(const std::string &msg);

    static bool deriveKey (const std::string &password, const unsigned char* salt, unsigned char *out_key );

    bool aesEncryptPayload(const unsigned char* compressedPayload, size_t inLen, 
                           unsigned char* encryptedPayload, size_t* outlen, 
                           const std::string &password
    );
    
    bool aesDecryptPayload(const unsigned char* encryptedPayload, size_t encryptedLen,
                           unsigned char* decryptedPayload, size_t* decryptedSize,
                           const std::string &password
    );
}