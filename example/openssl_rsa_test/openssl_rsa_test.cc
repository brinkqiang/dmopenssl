#include "dmrsa.h"

int main() {
    try {
        CDMRSAEncryptor rsaEncryptor;

        std::string plain_text = "Hello, RSA!";
        std::vector<unsigned char> encrypted_text = rsaEncryptor.publicEncrypt(plain_text);
        std::string decrypted_text = rsaEncryptor.privateDecrypt(encrypted_text);

        std::cout << "加密前：" << plain_text << std::endl;
        std::cout << "加密后：" << std::string(encrypted_text.begin(), encrypted_text.end()) << std::endl;
        std::cout << "解密后：" << decrypted_text << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}