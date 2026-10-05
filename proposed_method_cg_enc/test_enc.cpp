#include "crypto_utils.hpp"
#include <iostream>

int main() {
    std::string enc = CryptoUtils::encryptName("session-12345/1", "");
    std::cout << "Encrypted: " << enc << std::endl;
    return 0;
}
