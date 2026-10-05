import os

with open('producer.cpp', 'r') as f:
    content = f.read()

old_d3_recv = '''                std::string d3_content(reinterpret_cast<const char*>(d3.getContent().value()), d3.getContent().value_size());
                json d3_payload = json::parse(d3_content);
                std::string actual_data = d3_payload["data"];
                logPrint("[Producer] Received Data for chunk " + std::to_string(chunk_id) + ": " + actual_data);'''

new_d3_recv = '''                std::string d3_encrypted(reinterpret_cast<const char*>(d3.getContent().value()), d3.getContent().value_size());
                std::string d3_content;
                try {
                    d3_content = CryptoUtils::decryptName(d3_encrypted, m_sessionKey);
                } catch (...) {
                    logPrint("[Producer] Security Error: Decryption failed for D_3 chunk " + std::to_string(chunk_id));
                    return;
                }
                json d3_payload = json::parse(d3_content);
                std::string actual_data = d3_payload["data"];
                logPrint("[Producer] Received Data for chunk " + std::to_string(chunk_id) + ": " + actual_data);'''

content = content.replace(old_d3_recv, new_d3_recv)

with open('producer.cpp', 'w') as f:
    f.write(content)

print("Patched producer.cpp")
