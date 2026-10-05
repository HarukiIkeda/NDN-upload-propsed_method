#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <map>
#include <set>
#include <random>
#include <boost/asio/io_context.hpp>
#include "crypto_utils.hpp"

using namespace ndn;
using json = nlohmann::json;

struct SessionData {
    std::string consumer;
    std::string key;
    std::string key_cg;
    Name i1_name;
    int total_chunks;
    std::map<std::string, Name> i3_names;
    std::set<std::string> completed_chunks;
};

class Gateway {
public:
    Gateway() : m_face(), m_scheduler(m_face.getIoContext()) {}

    void run() {
        m_face.setInterestFilter("/gateway/upload-request",
            std::bind(&Gateway::onInterestI1, this, _1, _2),
            std::bind(&Gateway::onRegisterSuccess, this, _1),
            std::bind(&Gateway::onRegisterFailed, this, _1, _2));

        m_face.setInterestFilter("/gateway/fetch",
            std::bind(&Gateway::onInterestI3, this, _1, _2),
            std::bind(&Gateway::onRegisterSuccess, this, _1),
            std::bind(&Gateway::onRegisterFailed, this, _1, _2));

        m_scheduler.schedule(time::seconds(25), [this] {
            std::cout << "\n=== [EVALUATION] Gateway Metrics ===" << std::endl;
            std::cout << "Total Packets Exchanged: " 
                      << (metrics_rx_i + metrics_tx_i + metrics_tx_d + metrics_rx_d)
                      << " {'rx_i': " << metrics_rx_i << ", 'tx_i': " << metrics_tx_i
                      << ", 'tx_d': " << metrics_tx_d << ", 'rx_d': " << metrics_rx_d << "}" << std::endl;
            std::cout << "Max State Size (Pending Chunks): " << state_max_pending_chunks << std::endl;
            m_face.getIoContext().stop();
        });

        m_face.processEvents();
    }

private:
    void updateStateMetrics() {
        int current_size = 0;
        for (const auto& pair : session_table) {
            current_size += pair.second.i3_names.size();
        }
        state_current_pending_chunks = current_size;
        if (current_size > state_max_pending_chunks) {
            state_max_pending_chunks = current_size;
        }
    }

    void onInterestI1(const Name& prefix, const Interest& interest) {
        if (simulatePacketLoss()) {
            logPrint("[Gateway EVAL] Dropped I_1 to simulate packet loss");
            return;
        }
        metrics_rx_i++;

        const Name& name = interest.getName();
        size_t idx = 0;
        for (size_t i = 0; i < name.size(); ++i) {
            if (name[i].toUri() == "upload-request") {
                idx = i;
                break;
            }
        }
        if (idx + 1 >= name.size()) return;
        std::string session_id = name[idx + 1].toUri();

        if (!interest.hasApplicationParameters()) return;
        auto block = interest.getApplicationParameters();
        std::string app_param_str(reinterpret_cast<const char*>(block.value()), block.value_size());
        json payload = json::parse(app_param_str);

        logPrint("[Gateway] Received I_1 for session " + session_id + " from Consumer " + payload["consumer"].get<std::string>());

        SessionData sdata;
        sdata.consumer = payload["consumer"];
        sdata.i1_name = name;
        sdata.total_chunks = payload["chunk_size"];
        session_table[session_id] = sdata;

        auto keypair = CryptoUtils::generateKeyPair();
        EVP_PKEY* s_g = keypair.first;
        std::string p_g = keypair.second;
        session_table[session_id].key_cg = CryptoUtils::deriveSharedKey(s_g, payload["pub_key"]);

        json i2_param = {
            {"gateway", "/gateway"},
            {"chunk_size", payload["chunk_size"]},
            {"pub_key", p_g},
            {"start_time", payload["start_time"]}
        };
        std::string i2_param_str = i2_param.dump();

        Name i2_name(payload["producer"].get<std::string>());
        i2_name.append("setup").append(session_id);

        expressI2WithRetry(i2_name, i2_param_str, session_id, s_g, p_g, payload, 0);
    }

    void expressI2WithRetry(Name i2_name, std::string i2_param_str, std::string session_id, EVP_PKEY* s_g, std::string p_g, json payload, int retries) {
        if (retries > 3) {
            logPrint("[Gateway] Exhausted retries for setup I_2 for session " + session_id + ". Giving up.");
            EVP_PKEY_free(s_g);
            return;
        }

        if (retries > 0) {
            logPrint("[Gateway] Retrying setup I_2 for session " + session_id + " (Attempt " + std::to_string(retries) + ")");
        }

        Interest i2(i2_name);
        i2.setMustBeFresh(true);
        i2.setInterestLifetime(time::milliseconds(200)); // WAN timeout
        i2.setApplicationParameters(i2_param_str);

        metrics_tx_i++;
        m_face.expressInterest(i2,
            [this, session_id, s_g, p_g, payload](const Interest&, const Data& d2) {
                metrics_rx_d++;
                const Name& d2_name = d2.getName();
                size_t setup_idx = 0;
                for (size_t i = 0; i < d2_name.size(); ++i) {
                    if (d2_name[i].toUri() == "setup") {
                        setup_idx = i;
                        break;
                    }
                }
                std::string recv_session_id = d2_name[setup_idx + 1].toUri();
                logPrint("[Gateway] D_2 received from " + payload["producer"].get<std::string>());

                std::string d2_content(reinterpret_cast<const char*>(d2.getContent().value()), d2.getContent().value_size());
                json p_p_json = json::parse(d2_content);
                std::string p_p = p_p_json["pub_key"];

                std::string session_key = CryptoUtils::deriveSharedKey(s_g, p_p);
                session_table[recv_session_id].key = session_key;
                logPrint("[Gateway] Session established. Key secured.");

                EVP_PKEY_free(s_g);

                Name target_i1_name = session_table[recv_session_id].i1_name;
                logPrint("[Gateway] Sending Ack (D_1) back to Consumer");

                auto data = std::make_shared<Data>(target_i1_name);
                data->setFreshnessPeriod(time::milliseconds(1000));
                
                std::string encrypted_master_key = CryptoUtils::encryptName(session_key, session_table[recv_session_id].key_cg);
                json d1_payload = {
                    {"pub_key", p_g},
                    {"master_key", encrypted_master_key}
                };
                std::string content = d1_payload.dump();
                data->setContent(content);
                m_keyChain.sign(*data);
                m_face.put(*data);
                metrics_tx_d++;
            },
            [this, s_g](const Interest&, const lp::Nack&) {
                logPrint("[Gateway] Failed to setup with producer: Nack");
                EVP_PKEY_free(s_g);
            },
            [this, i2_name, i2_param_str, session_id, s_g, p_g, payload, retries](const Interest&) {
                logPrint("[Gateway] Timeout for setup I_2. Initiating local retransmission.");
                expressI2WithRetry(i2_name, i2_param_str, session_id, s_g, p_g, payload, retries + 1);
            }
        );
    }

    void expressI4WithRetry(Name i4_name, std::string target_session_id, std::string chunk_id, int retries) {
        if (retries > 3) {
            logPrint("[Gateway] Exhausted retries for chunk " + chunk_id + ". Giving up.");
            session_table[target_session_id].i3_names.erase(chunk_id);
            updateStateMetrics();
            return;
        }

        if (retries > 0) {
            logPrint("[Gateway] Retrying I_4 for chunk " + chunk_id + " (Attempt " + std::to_string(retries) + ")");
        }

        Interest i4(i4_name);
        i4.setMustBeFresh(true);
        i4.setInterestLifetime(time::milliseconds(40));
        metrics_tx_i++;

        m_face.expressInterest(i4,
            [this](const Interest&, const Data& d4) {
                metrics_rx_d++;
                
                // D_4の名前から暗号化されたコンポーネント（末尾）を取得
                const Name& d4_name = d4.getName();
                if (d4_name.empty()) return;
                std::string encrypted_component = d4_name[-1].toUri();
                
                std::string decrypted;
                std::string resolved_session_id;
                
                // テーブルのマスター鍵を使って復号し、セッションIDを特定
                for (const auto& pair : session_table) {
                    if (pair.second.key.empty()) continue;
                    try {
                        decrypted = CryptoUtils::decryptName(encrypted_component, pair.second.key);
                        resolved_session_id = pair.first;
                        break;
                    } catch (...) {
                        continue;
                    }
                }
                
                if (decrypted.empty()) {
                    logPrint("[Gateway] Security Error: Decryption failed for D_4 name.");
                    return;
                }
                
                size_t slash_pos = decrypted.find('/');
                if (slash_pos == std::string::npos) return;
                
                std::string chunk_id = decrypted.substr(slash_pos + 1);
                
                // If no pending I_3, it might have been fulfilled or cancelled
                if (session_table[resolved_session_id].i3_names.count(chunk_id) == 0) return;

                Name target_i3_name = session_table[resolved_session_id].i3_names[chunk_id];
                logPrint("[Gateway] Decrypted D_4 -> session: " + resolved_session_id + ", chunk: " + chunk_id);
                logPrint("[Gateway] Proxied chunk " + chunk_id + " back to Producer");

                auto data = std::make_shared<Data>(target_i3_name);
                data->setFreshnessPeriod(time::milliseconds(1000));
                data->setContent(d4.getContent());
                m_keyChain.sign(*data);
                m_face.put(*data);
                metrics_tx_d++;

                session_table[resolved_session_id].i3_names.erase(chunk_id);
                session_table[resolved_session_id].completed_chunks.insert(chunk_id);
                
                // Check if session is completely finished
                if (session_table[resolved_session_id].completed_chunks.size() == static_cast<size_t>(session_table[resolved_session_id].total_chunks)) {
                    logPrint("[Gateway] Session " + resolved_session_id + " completed all " + std::to_string(session_table[resolved_session_id].total_chunks) + " chunks. Cleaning up session state.");
                    session_table.erase(resolved_session_id);
                }
                
                updateStateMetrics();
            },
            [this, target_session_id, chunk_id](const Interest&, const lp::Nack&) {
                logPrint("[Gateway] Failed to fetch chunk from consumer: Nack");
                session_table[target_session_id].i3_names.erase(chunk_id);
                updateStateMetrics();
            },
            [this, target_session_id, chunk_id, i4_name, retries](const Interest&) {
                logPrint("[Gateway] Timeout for chunk " + chunk_id + " on edge. Initiating local retransmission.");
                expressI4WithRetry(i4_name, target_session_id, chunk_id, retries + 1);
            }
        );
    }

    void onInterestI3(const Name& prefix, const Interest& interest) {
        if (simulatePacketLoss()) {
            logPrint("[Gateway EVAL] Dropped I_3 to simulate packet loss");
            return;
        }
        metrics_rx_i++;

        try {
            const Name& name = interest.getName();
            size_t idx = 0;
            for (size_t i = 0; i < name.size(); ++i) {
                if (name[i].toUri() == "fetch") {
                    idx = i;
                    break;
                }
            }
            if (idx + 1 >= name.size()) return;
            std::string encrypted_component = name[idx + 1].toUri();

            logPrint("[Gateway] Received I_3: " + encrypted_component.substr(0, 15) + "...");

            std::string decrypted;
            std::string target_session_id;

            for (const auto& pair : session_table) {
                if (pair.second.key.empty()) continue;
                try {
                    decrypted = CryptoUtils::decryptName(encrypted_component, pair.second.key);
                    target_session_id = pair.first;
                    break;
                } catch (...) {
                    continue;
                }
            }

            if (decrypted.empty()) {
                logPrint("[Gateway] Security Error: Decryption failed. Dropped I_3.");
                return;
            }

            size_t slash_pos = decrypted.find('/');
            if (slash_pos == std::string::npos) return;

            std::string session_id = decrypted.substr(0, slash_pos);
            std::string chunk_id = decrypted.substr(slash_pos + 1);

            if (session_id != target_session_id) {
                logPrint("[Gateway] Security Error: Decrypted Session ID mismatch!");
                return;
            }

            logPrint("[Gateway] Decrypted I_3 -> session: " + session_id + ", chunk: " + chunk_id);

            if (session_table[target_session_id].completed_chunks.count(chunk_id)) {
                logPrint("[Gateway] Chunk " + chunk_id + " is already completed. Ignoring retransmitted I_3.");
                return;
            }

            if (session_table[target_session_id].i3_names.count(chunk_id)) {
                logPrint("[Gateway] I_3 for chunk " + chunk_id + " is already in progress. Updating pending name and skipping I_4.");
                session_table[target_session_id].i3_names[chunk_id] = name;
                return;
            }

            session_table[target_session_id].i3_names[chunk_id] = name;
            updateStateMetrics();

            std::string consumer_name = session_table[target_session_id].consumer;
            Name i4_name(consumer_name);
            i4_name.append("upload").append(encrypted_component);
            logPrint("[Gateway] Forwarding I_4 to Consumer: " + i4_name.toUri());

            expressI4WithRetry(i4_name, target_session_id, chunk_id, 0);

        } catch (const std::exception& e) {
            logPrint(std::string("[Gateway] Error in on_interest_i3: ") + e.what());
        }
    }

    void onRegisterSuccess(const Name& prefix) {}
    void onRegisterFailed(const Name& prefix, const std::string& reason) {
        logPrint("[Gateway] Failed to register prefix: " + reason);
    }

    void logPrint(const std::string& msg) {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) % 1000000;
        
        std::cout << "[" << std::put_time(std::localtime(&in_time_t), "%H:%M:%S") << "." 
                  << std::setfill('0') << std::setw(6) << ms.count() << "] " << msg << std::endl;
    }

    bool simulatePacketLoss() {
        return false;
    }

    Face m_face;
    KeyChain m_keyChain;
    Scheduler m_scheduler;
    std::map<std::string, SessionData> session_table;

    int metrics_rx_i = 0;
    int metrics_tx_i = 0;
    int metrics_tx_d = 0;
    int metrics_rx_d = 0;
    int state_current_pending_chunks = 0;
    int state_max_pending_chunks = 0;
};

int main() {
    try {
        Gateway app;
        app.run();
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}
