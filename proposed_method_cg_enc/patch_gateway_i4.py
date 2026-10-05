import os

with open('gateway.cpp', 'r') as f:
    content = f.read()

old_i4 = '''            std::string consumer_name = session_table[target_session_id].consumer;
            Name i4_name(consumer_name);
            i4_name.append("upload").append(session_id).append(chunk_id);
            logPrint("[Gateway] Forwarding I_4 to Consumer: " + i4_name.toUri());'''

new_i4 = '''            std::string consumer_name = session_table[target_session_id].consumer;
            Name i4_name(consumer_name);
            std::string plain_name = session_id + "/" + chunk_id;
            std::string encrypted_name = CryptoUtils::encryptName(plain_name, session_table[target_session_id].key_cg);
            i4_name.append("upload").append(encrypted_name);
            logPrint("[Gateway] Forwarding I_4 to Consumer: " + i4_name.toUri());'''

if old_i4 in content:
    content = content.replace(old_i4, new_i4)
    print("Successfully patched i4_name encryption.")
else:
    print("Warning: old_i4 not found in gateway.cpp")

with open('gateway.cpp', 'w') as f:
    f.write(content)
