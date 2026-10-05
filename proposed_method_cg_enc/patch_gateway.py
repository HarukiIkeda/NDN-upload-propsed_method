import os

with open('gateway.cpp', 'r') as f:
    content = f.read()

# 1. SessionData
content = content.replace('std::string key;', 'std::string key;\n    std::string key_cg;')

# 2. onInterestI1 key_cg derivation
content = content.replace('std::string p_g = keypair.second;', 'std::string p_g = keypair.second;\n        session_table[session_id].key_cg = CryptoUtils::deriveSharedKey(s_g, payload["pub_key"]);')

# 3. expressI2WithRetry signature and invocation
content = content.replace('expressI2WithRetry(i2_name, i2_param_str, session_id, s_g, payload, 0);', 'expressI2WithRetry(i2_name, i2_param_str, session_id, s_g, p_g, payload, 0);')
content = content.replace('void expressI2WithRetry(Name i2_name, std::string i2_param_str, std::string session_id, EVP_PKEY* s_g, json payload, int retries)', 'void expressI2WithRetry(Name i2_name, std::string i2_param_str, std::string session_id, EVP_PKEY* s_g, std::string p_g, json payload, int retries)')
content = content.replace('[this, session_id, s_g, payload](const Interest&, const Data& d2)', '[this, session_id, s_g, p_g, payload](const Interest&, const Data& d2)')

# 4. D_1 payload modification
old_d1 = '''                std::string content = "Ack";
                data->setContent(content);'''
new_d1 = '''                json d1_payload = {{"pub_key", p_g}};
                std::string content = d1_payload.dump();
                data->setContent(content);'''
content = content.replace(old_d1, new_d1)

# 5. expressI4WithRetry i4 name encryption
old_i4_name = '''        Name i4(target_i1_name);
        i4.append("upload").append(target_session_id).append(chunk_id);'''
new_i4_name = '''        std::string plain_name = target_session_id + "/" + chunk_id;
        std::string encrypted_name = CryptoUtils::encryptName(plain_name, session_table[target_session_id].key_cg);
        Name i4(target_i1_name);
        i4.append("upload").append(encrypted_name);'''
content = content.replace(old_i4_name, new_i4_name)

# 6. onDataI4 payload decryption and re-encryption
old_d4_recv = '''                std::string d4_content(reinterpret_cast<const char*>(d4.getContent().value()), d4.getContent().value_size());
                json d4_payload = json::parse(d4_content);
                std::string recv_session_id = d4_payload["session_id"];
                std::string recv_chunk_id = std::to_string(d4_payload["chunk_id"].get<int>());

                // If no pending I_3, it might have been fulfilled or cancelled
                if (session_table[recv_session_id].i3_names.count(recv_chunk_id) == 0) return;

                Name target_i3_name = session_table[recv_session_id].i3_names[recv_chunk_id];
                logPrint("[Gateway] Proxied chunk " + recv_chunk_id + " back to Producer");

                auto data = std::make_shared<Data>(target_i3_name);
                data->setFreshnessPeriod(time::milliseconds(1000));
                data->setContent(d4.getContent());'''

new_d4_recv = '''                std::string d4_encrypted(reinterpret_cast<const char*>(d4.getContent().value()), d4.getContent().value_size());
                std::string d4_content;
                try {
                    d4_content = CryptoUtils::decryptName(d4_encrypted, session_table[target_session_id].key_cg);
                } catch (...) {
                    logPrint("[Gateway] Security Error: Decryption failed for D_4.");
                    return;
                }
                json d4_payload = json::parse(d4_content);
                std::string recv_session_id = d4_payload["session_id"];
                std::string recv_chunk_id = std::to_string(d4_payload["chunk_id"].get<int>());

                // If no pending I_3, it might have been fulfilled or cancelled
                if (session_table[recv_session_id].i3_names.count(recv_chunk_id) == 0) return;

                Name target_i3_name = session_table[recv_session_id].i3_names[recv_chunk_id];
                logPrint("[Gateway] Proxied chunk " + recv_chunk_id + " back to Producer");

                std::string re_encrypted = CryptoUtils::encryptName(d4_content, session_table[recv_session_id].key);

                auto data = std::make_shared<Data>(target_i3_name);
                data->setFreshnessPeriod(time::milliseconds(1000));
                data->setContent(re_encrypted);'''
content = content.replace(old_d4_recv, new_d4_recv)

with open('gateway.cpp', 'w') as f:
    f.write(content)

print("Patched gateway.cpp")
