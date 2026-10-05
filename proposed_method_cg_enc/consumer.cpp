#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <boost/asio/io_context.hpp>
#include "crypto_utils.hpp"

using namespace ndn;
using json = nlohmann::json;

class Consumer {
public:
    Consumer(const std::string& gateway_prefix, const std::string& producer_prefix, const std::string& session_id, int chunk_size)
        : m_face(), m_scheduler(m_face.getIoContext()),
          m_gatewayPrefix(gateway_prefix), m_producerPrefix(producer_prefix),
          m_sessionId(session_id), m_chunkSize(chunk_size), m_sc(nullptr) {}

    ~Consumer() {
        if (m_sc) EVP_PKEY_free(m_sc);
    }

    void run() {
        // Waiting silently for network convergence
        m_scheduler.schedule(time::seconds(5), [this] { startUpload(); });

        m_face.setInterestFilter("/local/consumer1/upload",
            std::bind(&Consumer::onInterestI4, this, _1, _2),
            std::bind(&Consumer::onRegisterSuccess, this, _1),
            std::bind(&Consumer::onRegisterFailed, this, _1, _2));

        // The 25-second absolute wait has been removed.
        // Consumer will exit cleanly when it sends the final chunk.

        m_face.processEvents();
    }

private:
    void startUpload() {
        Name name(m_gatewayPrefix);
        name.append("upload-request").append(m_sessionId);

        auto keypair = CryptoUtils::generateKeyPair();
        m_sc = keypair.first;
        std::string p_c = keypair.second;

        auto now = std::chrono::system_clock::now().time_since_epoch();
        double start_time = std::chrono::duration<double>(now).count();

        json app_param = {
            {"consumer", "/local/consumer1"},
            {"producer", m_producerPrefix},
            {"chunk_size", m_chunkSize},
            {"start_time", start_time},
            {"pub_key", p_c}
        };

        std::string app_param_str = app_param.dump();
        
        Interest interest(name);
        interest.setMustBeFresh(true);
        interest.setInterestLifetime(time::milliseconds(1000));
        interest.setApplicationParameters(app_param_str);

        logPrint("[Consumer] Sending I_1 for session " + m_sessionId);
        metrics_tx_i++;

        m_face.expressInterest(interest,
            std::bind(&Consumer::onDataI1, this, _1, _2),
            std::bind(&Consumer::onNackI1, this, _1, _2),
            std::bind(&Consumer::onTimeoutI1, this, _1));
    }

    void onDataI1(const Interest&, const Data& data) {
        metrics_rx_d++;
        std::string d1_content(reinterpret_cast<const char*>(data.getContent().value()), data.getContent().value_size());
        json p_g_json = json::parse(d1_content);
        std::string p_g = p_g_json["pub_key"];

        m_sessionKeyCG = CryptoUtils::deriveSharedKey(m_sc, p_g);
        EVP_PKEY_free(m_sc);
        m_sc = nullptr;
        
        std::string encrypted_master = p_g_json["master_key"];
        m_sessionKey = CryptoUtils::decryptName(encrypted_master, m_sessionKeyCG);

        logPrint("[Consumer] Received Ack (D_1). Master Session key established. Waiting for chunk requests...");
    }

    void onNackI1(const Interest&, const lp::Nack&) {
        logPrint("[Consumer] Failed to start upload: Nack");
    }

    void onTimeoutI1(const Interest&) {
        logPrint("[Consumer] Failed to start upload: Timeout");
        if (m_setupRetries < 5) {
            m_setupRetries++;
            logPrint("[Consumer] Retrying I_1 (Attempt " + std::to_string(m_setupRetries) + ")");
            startUpload();
        } else {
            logPrint("[Consumer] Max setup retries reached. Stopping.");
            m_face.getIoContext().stop();
        }
    }

    void onInterestI4(const Name& prefix, const Interest& interest) {
        metrics_rx_i++;
        try {
            const Name& name = interest.getName();
            bool found = false;
            size_t idx = 0;
            for (size_t i = 0; i < name.size(); ++i) {
                if (name[i].toUri() == "upload") {
                    idx = i;
                    found = true;
                    break;
                }
            }
            if (!found || idx + 1 >= name.size()) return;

            std::string encrypted_component = name[idx + 1].toUri();
            std::string decrypted;
            try {
                decrypted = CryptoUtils::decryptName(encrypted_component, m_sessionKey);
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
            std::string encrypted_payload = CryptoUtils::encryptName(payload_str, m_sessionKey);

            auto data = std::make_shared<Data>(name);
            data->setFreshnessPeriod(time::milliseconds(1000));
            data->setContent(encrypted_payload);
            m_keyChain.sign(*data);

            logPrint("[Consumer] Sending Data D_4 for chunk " + std::to_string(chunk_id));
            m_face.put(*data);
            metrics_tx_d++;

            if (chunk_id == m_chunkSize) {
                m_scheduler.schedule(time::milliseconds(500), [this] {
                    logPrint("[Consumer] All chunks sent. Shutting down.");
                    std::cout << "\n=== [EVALUATION] Consumer Metrics ===" << std::endl;
                    std::cout << "Total Packets Exchanged: " 
                              << (metrics_rx_i + metrics_tx_i + metrics_tx_d + metrics_rx_d)
                              << " {'rx_i': " << metrics_rx_i << ", 'tx_i': " << metrics_tx_i
                              << ", 'tx_d': " << metrics_tx_d << ", 'rx_d': " << metrics_rx_d << "}" << std::endl;
                    m_face.getIoContext().stop();
                });
            }
        } catch (const std::exception& e) {
            logPrint(std::string("[Consumer] Error in on_interest_i4: ") + e.what());
        }
    }

    void onRegisterSuccess(const Name& prefix) {}
    void onRegisterFailed(const Name& prefix, const std::string& reason) {
        logPrint("[Consumer] Failed to register prefix: " + reason);
    }

    void logPrint(const std::string& msg) {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) % 1000000;
        
        std::cout << "[" << std::put_time(std::localtime(&in_time_t), "%H:%M:%S") << "." 
                  << std::setfill('0') << std::setw(6) << ms.count() << "] " << msg << std::endl;
    }

    Face m_face;
    KeyChain m_keyChain;
    Scheduler m_scheduler;
    std::string m_gatewayPrefix;
    std::string m_producerPrefix;
    std::string m_sessionId;
    int m_chunkSize;

    int metrics_rx_i = 0;
    int metrics_tx_i = 0;
    int metrics_tx_d = 0;
    int metrics_rx_d = 0;
    int m_setupRetries = 0;

    EVP_PKEY* m_sc;
    std::string m_sessionKeyCG;
    std::string m_sessionKey;
};

int main() {
    try {
        int chunk_size = 50;
        const char* env_chunk = std::getenv("CHUNK_SIZE");
        if (env_chunk) {
            chunk_size = std::stoi(env_chunk);
        }
        std::cout << "Starting Consumer with CHUNK_SIZE=" << chunk_size << std::endl;
        Consumer app("/gateway", "/producer", "session-12345", chunk_size);
        app.run();
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}
