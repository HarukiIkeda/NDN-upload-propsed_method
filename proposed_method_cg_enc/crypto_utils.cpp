#include "crypto_utils.hpp"
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdexcept>
#include <cstring>
#include <iostream>

std::pair<EVP_PKEY*, std::string> CryptoUtils::generateKeyPair() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    std::vector<uint8_t> pub_pem(bptr->data, bptr->data + bptr->length);
    BIO_free(bio);

    return {pkey, base64Encode(pub_pem)};
}

std::string CryptoUtils::deriveSharedKey(EVP_PKEY* privKey, const std::string& peerPubBase64) {
    std::vector<uint8_t> peer_pem = base64Decode(peerPubBase64);
    BIO *bio = BIO_new_mem_buf(peer_pem.data(), peer_pem.size());
    EVP_PKEY *peerKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privKey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peerKey);
    
    size_t secretLen;
    EVP_PKEY_derive(ctx, NULL, &secretLen);
    std::vector<uint8_t> secret(secretLen);
    EVP_PKEY_derive(ctx, secret.data(), &secretLen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerKey);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(kctx);
    EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(kctx, secret.data(), secretLen);
    EVP_PKEY_CTX_add1_hkdf_info(kctx, (const unsigned char*)"ndn-upload-protocol", 19);

    size_t outLen = 32;
    std::vector<uint8_t> derived(outLen);
    EVP_PKEY_derive(kctx, derived.data(), &outLen);
    EVP_PKEY_CTX_free(kctx);

    return base64UrlEncode(derived);
}

std::string CryptoUtils::encryptName(const std::string& plainText, const std::string& sessionKeyBase64) {
    std::vector<uint8_t> key = base64UrlDecode(sessionKeyBase64);
    std::vector<uint8_t> iv(12);
    RAND_bytes(iv.data(), 12);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

    std::vector<uint8_t> ciphertext(plainText.length() + EVP_MAX_BLOCK_LENGTH);
    int len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (uint8_t*)plainText.c_str(), plainText.length());
    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    std::vector<uint8_t> tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> result;
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    result.insert(result.end(), tag.begin(), tag.end());

    std::string b64 = base64UrlEncode(result);
    // Remove padding '='
    while (!b64.empty() && b64.back() == '=') {
        b64.pop_back();
    }
    return b64;
}

std::string CryptoUtils::decryptName(const std::string& cipherTextBase64, const std::string& sessionKeyBase64) {
    std::string padded = cipherTextBase64;
    while (padded.length() % 4 != 0) {
        padded += "=";
    }
    std::vector<uint8_t> key = base64UrlDecode(sessionKeyBase64);
    std::vector<uint8_t> data = base64UrlDecode(padded);

    if (data.size() < 12 + 16) throw std::runtime_error("Invalid ciphertext size");

    std::vector<uint8_t> iv(data.begin(), data.begin() + 12);
    std::vector<uint8_t> tag(data.end() - 16, data.end());
    std::vector<uint8_t> ciphertext(data.begin() + 12, data.end() - 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

    std::vector<uint8_t> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) throw std::runtime_error("Decryption failed");
    plaintext_len += len;

    return std::string((char*)plaintext.data(), plaintext_len);
}

std::string CryptoUtils::base64Encode(const std::vector<uint8_t>& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string res(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return res;
}

std::vector<uint8_t> CryptoUtils::base64Decode(const std::string& input) {
    BIO *bio, *b64;
    std::vector<uint8_t> buffer(input.size());

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(input.c_str(), input.size());
    bio = BIO_push(b64, bio);

    int length = BIO_read(bio, buffer.data(), input.size());
    BIO_free_all(bio);
    if (length < 0) return {};
    buffer.resize(length);
    return buffer;
}

std::string CryptoUtils::base64UrlEncode(const std::vector<uint8_t>& data) {
    std::string b64 = base64Encode(data);
    for (char& c : b64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return b64;
}

std::vector<uint8_t> CryptoUtils::base64UrlDecode(const std::string& input) {
    std::string b64 = input;
    for (char& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    return base64Decode(b64);
}
