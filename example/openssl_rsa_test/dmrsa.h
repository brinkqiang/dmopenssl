
#ifndef __DMRSA_H__
#define __DMRSA_H__

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string>

class CDMRSAEncryptor {
public:
    CDMRSAEncryptor() {
        rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    }

    ~CDMRSAEncryptor() {
        RSA_free(rsa);
    }

    std::string publicEncrypt(const std::string& plain_text) {
        unsigned char encrypted[256] = {0};
        int encrypted_len = RSA_public_encrypt(plain_text.size(), reinterpret_cast<const unsigned char *>(plain_text.c_str()), encrypted, rsa, RSA_PKCS1_PADDING);
        return std::string(reinterpret_cast<char*>(encrypted), encrypted_len);
    }

    std::string privateDecrypt(const std::string& encrypted_text) {
        unsigned char decrypted[256] = {0};
        int decrypted_len = RSA_private_decrypt(encrypted_text.size(), reinterpret_cast<const unsigned char *>(encrypted_text.c_str()), decrypted, rsa, RSA_PKCS1_PADDING);
        return std::string(reinterpret_cast<char*>(decrypted), decrypted_len);
    }

private:
    RSA *rsa;
};

#endif // __DMRSA_H__
