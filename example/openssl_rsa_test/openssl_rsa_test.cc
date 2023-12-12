
#include "dmrsa.h"

int main() {
    CDMRSAEncryptor rsaEncryptor;

    std::string plain_text = "Hello, RSA!";
    std::string encrypted_text = rsaEncryptor.publicEncrypt(plain_text);
    std::string decrypted_text = rsaEncryptor.privateDecrypt(encrypted_text);

    std::cout << "加密前：" << plain_text << std::endl;
    std::cout << "加密后：" << encrypted_text << std::endl;
    std::cout << "解密后：" << decrypted_text << std::endl;

    return 0;
}
