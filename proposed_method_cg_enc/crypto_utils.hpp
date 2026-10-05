#ifndef CRYPTO_UTILS_HPP
#define CRYPTO_UTILS_HPP

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <utility>
#include <cstdint>

class CryptoUtils {
public:
    // Generate SECP256R1 Keypair
    // Returns {private_key_ptr, public_key_pem_base64_string}
    static std::pair<EVP_PKEY*, std::string> generateKeyPair();

    // Derive Shared Key using private key and peer's public key (PEM Base64)
    // Returns 32-byte URL-safe base64 string
    static std::string deriveSharedKey(EVP_PKEY* privKey, const std::string& peerPubBase64);

    // Encrypt string with AES-256-GCM using the base64 session key
    // Returns base64url string without padding
    static std::string encryptName(const std::string& plainText, const std::string& sessionKeyBase64);

    // Decrypt base64url string with AES-256-GCM using the base64 session key
    // Returns plain string
    static std::string decryptName(const std::string& cipherTextBase64, const std::string& sessionKeyBase64);

    static std::string base64UrlEncode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64UrlDecode(const std::string& input);
    
    static std::string base64Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64Decode(const std::string& input);
};

#endif
