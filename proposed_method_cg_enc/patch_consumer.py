import os

with open('consumer.cpp', 'r') as f:
    content = f.read()

content = content.replace('#include <boost/asio/io_context.hpp>', '#include <boost/asio/io_context.hpp>\n#include "crypto_utils.hpp"')

content = content.replace('m_chunkSize(chunk_size) {}', 'm_chunkSize(chunk_size), m_sc(nullptr) {}\n\n    ~Consumer() {\n        if (m_sc) EVP_PKEY_free(m_sc);\n    }')

content = content.replace('"start_time", start_time}', '"start_time", start_time},\n            {"pub_key", p_c}')

content = content.replace('auto now = std::chrono::system_clock::now().time_since_epoch();', 'auto keypair = CryptoUtils::generateKeyPair();\n        m_sc = keypair.first;\n        std::string p_c = keypair.second;\n\n        auto now = std::chrono::system_clock::now().time_since_epoch();')

content = content.replace('    void onDataI1(const Interest&, const Data& data) {\n        metrics_rx_d++;\n        logPrint("[Consumer] Received Ack (D_1). Waiting for chunk requests...");\n    }', '    void onDataI1(const Interest&, const Data& data) {\n        metrics_rx_d++;\n        std::string d1_content(reinterpret_cast<const char*>(data.getContent().value()), data.getContent().value_size());\n        json p_g_json = json::parse(d1_content);\n        std::string p_g = p_g_json["pub_key"];\n\n        m_sessionKeyCG = CryptoUtils::deriveSharedKey(m_sc, p_g);\n        EVP_PKEY_free(m_sc);\n        m_sc = nullptr;\n\n        logPrint("[Consumer] Received Ack (D_1). Session key established. Waiting for chunk requests...");\n    }')

i4_old = '''            if (!found || idx + 2 >= name.size()) return;

            std::string session_id = name[idx + 1].toUri();
            int chunk_id = std::stoi(name[idx + 2].toUri());

            logPrint("[Consumer] Received I_4! Requesting chunk " + std::to_string(chunk_id));

            json payload = {
                {"session_id", session_id},
                {"chunk_id", chunk_id},
                {"data", "This is chunk " + std::to_string(chunk_id) + " for session " + session_id}
            };

            std::string payload_str = payload.dump();

            auto data = std::make_shared<Data>(name);
            data->setFreshnessPeriod(time::milliseconds(1000));
            data->setContent(payload_str);
            m_keyChain.sign(*data);'''

i4_new = '''            if (!found || idx + 1 >= name.size()) return;

            std::string encrypted_component = name[idx + 1].toUri();
            std::string decrypted;
            try {
                decrypted = CryptoUtils::decryptName(encrypted_component, m_sessionKeyCG);
            } catch (...) {
                logPrint("[Consumer] Security Error: Decryption failed for I_4.");
                return;
            }

            size_t slash_pos = decrypted.find('/');
            if (slash_pos == std::string::npos) return;

            std::string session_id = decrypted.substr(0, slash_pos);
            int chunk_id = std::stoi(decrypted.substr(slash_pos + 1));

            logPrint("[Consumer] Received I_4! Decrypted request for chunk " + std::to_string(chunk_id));

            json payload = {
                {"session_id", session_id},
                {"chunk_id", chunk_id},
                {"data", "This is chunk " + std::to_string(chunk_id) + " for session " + session_id}
            };

            std::string payload_str = payload.dump();
            std::string encrypted_payload = CryptoUtils::encryptName(payload_str, m_sessionKeyCG);

            auto data = std::make_shared<Data>(name);
            data->setFreshnessPeriod(time::milliseconds(1000));
            data->setContent(encrypted_payload);
            m_keyChain.sign(*data);'''

content = content.replace(i4_old, i4_new)

content = content.replace('    int m_setupRetries = 0;\n};', '    int m_setupRetries = 0;\n\n    EVP_PKEY* m_sc;\n    std::string m_sessionKeyCG;\n};')

with open('consumer.cpp', 'w') as f:
    f.write(content)

print("Patched consumer.cpp")
