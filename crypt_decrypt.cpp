#include "crypt_decrypt.h"




    static void AESGCM::print_openssl_error(const std::string &msg) {
    std::cerr << msg << "\n";
    ERR_print_errors_fp(stderr);
    }

    static bool AESGCM::deriveKey (const std::string &password, const unsigned char* salt, unsigned char *out_key ) {
    if (!PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        salt,
        SALT_LEN,
        PBKDF2_ITER,
        EVP_sha256(),
        KEY_LEN,
        out_key
                          )
    ) {print_openssl_error("PKCS5_PBKDF2_HMAC failed"); return false;}
       return true;
    }


    bool AESGCM::aesEncryptPayload(const unsigned char* compressedPayload, size_t inLen, 
                           unsigned char* encryptedPayload, size_t* outlen, 
                           const std::string &password
    ) {
        size_t totalWritten = 0;
        unsigned char salt[SALT_LEN];
        unsigned char IV[IV_LEN];
        
        if (RAND_bytes(salt, SALT_LEN) != 1) {print_openssl_error("RAND_bytes(salt, SALT_LEN) failed!\n"); return false;}
        if (RAND_bytes(IV, IV_LEN) != 1) {print_openssl_error("RAND_bytes(IV, IV_LEN) failed!\n"); return false;}

        unsigned char key[KEY_LEN];
        if(!deriveKey(password, salt, key)) {return false;}

        memcpy(encryptedPayload + totalWritten, salt, SALT_LEN); totalWritten += SALT_LEN;
        memcpy(encryptedPayload + totalWritten, IV, IV_LEN); totalWritten += IV_LEN;
     
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {print_openssl_error("EVP_CIPHER_CTX_new() failed!\n"); return false;}
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {print_openssl_error("EVP_EncryptInit_ex failed!\n"); EVP_CIPHER_CTX_free(ctx); return false;}
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr)) {print_openssl_error("EVP_CIPHER_CTX_ctrl set IV_LEN failed!\n"); EVP_CIPHER_CTX_free(ctx); return false;}
        if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, IV)) {print_openssl_error("EVP_EncryptInit_ex set key/IV failed!\n"); EVP_CIPHER_CTX_free(ctx); return false;}

        int outLength = 0;
        if (!EVP_EncryptUpdate(ctx, encryptedPayload + totalWritten, &outLength, 
                              compressedPayload, (int)inLen)
           ) {
            
            print_openssl_error("EVP_EncryptUpdate() failed!\n");
            EVP_CIPHER_CTX_free(ctx);
            OPENSSL_cleanse(key, KEY_LEN);
            return false;
        }
        totalWritten += outLength;

        if (!EVP_EncryptFinal_ex(ctx, encryptedPayload + totalWritten, &outLength)) {printf("EVP_EncryptFinal_ex() is failed!\n"); EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, KEY_LEN); return false; }
        totalWritten += outLength;

        unsigned char tag[TAG_LEN];
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) {print_openssl_error("EVP_CIPHER_CTX_ctrl set TAG failed!\n"); EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, KEY_LEN); return false; }
        memcpy(encryptedPayload + totalWritten, tag, TAG_LEN);
        totalWritten += TAG_LEN;
        
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, KEY_LEN);
        *outlen = totalWritten;
        return true;
    }
    





    bool AESGCM::aesDecryptPayload(const unsigned char* encryptedPayload, size_t encryptedLen,
                    unsigned char* decryptedPayload, size_t* decryptedSize,
                    const std::string &password
    ) {	
		size_t offset = 0;
        size_t totalDecrypted = 0;
        unsigned char salt[SALT_LEN];
        unsigned char IV[IV_LEN];

        if(encryptedLen < SALT_LEN + IV_LEN + TAG_LEN) {printf("Encrypted File size is too small!\n"); return false;}
        memcpy(salt, encryptedPayload + offset, SALT_LEN); offset += SALT_LEN;
        memcpy(IV, encryptedPayload + offset, IV_LEN); offset += IV_LEN;
        size_t ciphertextlen = encryptedLen - SALT_LEN - IV_LEN - TAG_LEN;

        unsigned char tag[TAG_LEN];
        memcpy(tag, encryptedPayload + SALT_LEN + IV_LEN + ciphertextlen, TAG_LEN);

        unsigned char key[KEY_LEN];
        if (!deriveKey(password, salt, key)) {printf("deriveKey() failed!\n"); return false;} 

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(!ctx) {print_openssl_error("EVA_CIPHER_CTX_new failed!\n"); return false;}
        if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {print_openssl_error("EVP_DecryptInit_ex failed!\n"); EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, KEY_LEN); return false;}
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr)) {print_openssl_error("EVP_CIPHER_CTX_ctrl set IV_LEN failed!\n"); EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, KEY_LEN); return false;}
        if(!EVP_DecryptInit_ex(ctx,nullptr, nullptr, key, IV)) {print_openssl_error("EVP_DecryptInit_ex set key/IV failed!\n"); EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, KEY_LEN); return false;}

        int outLength = 0;
        if(!EVP_DecryptUpdate(ctx, decryptedPayload, &outLength, encryptedPayload + SALT_LEN + IV_LEN, ciphertextlen)) {print_openssl_error("EVP_DecryptUpdate failed!\n"); OPENSSL_cleanse(key, KEY_LEN); EVP_CIPHER_CTX_free(ctx); return false;}
        totalDecrypted += outLength;

        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag)) {print_openssl_error("EVP_CIPHER_CTX_ctrl set tag failed!\n"); EVP_CIPHER_CTX_free(ctx); OPENSSL_cleanse(key, KEY_LEN); return false;}

        if(!EVP_DecryptFinal_ex(ctx, decryptedPayload + totalDecrypted, &outLength)) {
            print_openssl_error("EVP_DecryptFinal_ex failed!\n"); 
            OPENSSL_cleanse(key, KEY_LEN); 
            EVP_CIPHER_CTX_free(ctx); 
            memset(decryptedPayload, 0, totalDecrypted);
            if(decryptedSize) {*decryptedSize = 0;}
            return false;
        }
        totalDecrypted += outLength;

        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, KEY_LEN);
        *decryptedSize = totalDecrypted;
        return true;
    }