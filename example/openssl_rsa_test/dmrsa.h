
#ifndef __DMRSA_H__
#define __DMRSA_H__

#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string>
#include <vector>

class CDMRSAEncryptor {
public:
    CDMRSAEncryptor() {
        rsa = RSA_new();
        BIGNUM* bne = BN_new();
        BN_set_word(bne, RSA_F4);
        if (RSA_generate_key_ex(rsa, 2048, bne, nullptr) != 1) {
            throw std::runtime_error("RSA key generation failed");
        }
        BN_free(bne);
    }

    ~CDMRSAEncryptor() {
        RSA_free(rsa);
    }

    std::vector<unsigned char> publicEncrypt(const std::string& plain_text) {
        std::vector<unsigned char> encrypted(RSA_size(rsa));
        int encrypted_len = RSA_public_encrypt(plain_text.size(), reinterpret_cast<const unsigned char*>(plain_text.c_str()), encrypted.data(), rsa, RSA_PKCS1_PADDING);
        if (encrypted_len == -1) {
            throw std::runtime_error("RSA public encryption failed");
        }
        encrypted.resize(encrypted_len);
        return encrypted;
    }

    std::string privateDecrypt(const std::vector<unsigned char>& encrypted_text) {
        std::vector<unsigned char> decrypted(RSA_size(rsa));
        int decrypted_len = RSA_private_decrypt(encrypted_text.size(), encrypted_text.data(), decrypted.data(), rsa, RSA_PKCS1_PADDING);
        if (decrypted_len == -1) {
            throw std::runtime_error("RSA private decryption failed");
        }
        decrypted.resize(decrypted_len);
        return std::string(decrypted.begin(), decrypted.end());
    }

private:
    RSA* rsa;
};

#endif // __DMRSA_H__
