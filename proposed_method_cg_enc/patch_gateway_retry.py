import os

with open('gateway.cpp', 'r') as f:
    content = f.read()

old_retry = '''            [this, i2_name, i2_param_str, session_id, s_g, payload, retries](const Interest&) {
                logPrint("[Gateway] Timeout for setup I_2. Initiating local retransmission.");
                expressI2WithRetry(i2_name, i2_param_str, session_id, s_g, payload, retries + 1);
            }'''

new_retry = '''            [this, i2_name, i2_param_str, session_id, s_g, p_g, payload, retries](const Interest&) {
                logPrint("[Gateway] Timeout for setup I_2. Initiating local retransmission.");
                expressI2WithRetry(i2_name, i2_param_str, session_id, s_g, p_g, payload, retries + 1);
            }'''

content = content.replace(old_retry, new_retry)

with open('gateway.cpp', 'w') as f:
    f.write(content)

print("Patched gateway.cpp retry logic")
