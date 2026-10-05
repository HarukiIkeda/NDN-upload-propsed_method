#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <nlohmann/json.hpp>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <deque>
#include <cstdlib>
#include <boost/asio/io_context.hpp>
#include "crypto_utils.hpp"

using namespace ndn;
using json = nlohmann::json;

class Producer {
public:
    Producer() : m_face(), m_scheduler(m_face.getIoContext()) {
        if (const char* ws_env = std::getenv("WINDOW_SIZE")) {
            m_windowSize = std::stoi(ws_env);
        }
    }

    void run() {
        m_face.setInterestFilter("/producer/setup",
            std::bind(&Producer::onInterestI2, this, _1, _2),
            std::bind(&Producer::onRegisterSuccess, this, _1),
            std::bind(&Producer::onRegisterFailed, this, _1, _2));

        m_face.processEvents();
    }

private:
    void onInterestI2(const Name& prefix, const Interest& interest) {
        metrics_rx_i++;
        const Name& name = interest.getName();
        size_t idx = 0;
        for (size_t i = 0; i < name.size(); ++i) {
            if (name[i].toUri() == "setup") {
                idx = i;
                break;
            }
        }
        if (idx + 1 >= name.size()) return;
        std::string session_id = name[idx + 1].toUri();

        logPrint("[Producer] Received I_2 for session " + session_id);

        if (!interest.hasApplicationParameters()) return;
        auto block = interest.getApplicationParameters();
        std::string app_param_str(reinterpret_cast<const char*>(block.value()), block.value_size());
        json payload = json::parse(app_param_str);

        std::string p_g = payload["pub_key"];
        std::string gateway_name = payload["gateway"];
        int chunk_size = payload["chunk_size"];
        double start_time = payload["start_time"];

        auto keypair = CryptoUtils::generateKeyPair();
        EVP_PKEY* s_p = keypair.first;
        std::string p_p = keypair.second;

        std::string session_key = CryptoUtils::deriveSharedKey(s_p, p_g);
        EVP_PKEY_free(s_p);
        logPrint("[Producer] Generated the session key for session " + session_id);

        json d2_payload = {{"pub_key", p_p}};
        std::string d2_payload_str = d2_payload.dump();

        auto data = std::make_shared<Data>(name);
        data->setFreshnessPeriod(time::milliseconds(1000));
        data->setContent(d2_payload_str);
        m_keyChain.sign(*data);

        m_face.put(*data);
        metrics_tx_d++;
        logPrint("[Producer] Transmitting D_2 with producer public key for session " + session_id);

        // Schedule pipeline fetch
        m_scheduler.schedule(time::milliseconds(10), [=] {
            fetchChunksPipeline(gateway_name, session_id, chunk_size, session_key, start_time);
        });
    }

    void fetchChunksPipeline(std::string gateway_name, std::string session_id, int chunk_size, std::string session_key, double start_time) {
        logPrint("[Producer] Starting pipeline fetch for " + std::to_string(chunk_size) + " chunks (Window: " + std::to_string(m_windowSize) + ")");
        
        m_gatewayName = gateway_name;
        m_sessionId = session_id;
        m_chunkSize = chunk_size;
        m_sessionKey = session_key;
        m_startTime = start_time;
        m_successCount = 0;
        m_nextChunkId = 1;
        m_activeTasks = 0;

        for (int i = 0; i < m_windowSize && m_nextChunkId <= m_chunkSize; ++i) {
            fetchSingleChunk(m_nextChunkId++);
        }
    }

    void fetchSingleChunk(int chunk_id, int attempt = 1) {
        if (attempt == 1) {
            m_activeTasks++;
        }

        std::string plain_name = m_sessionId + "/" + std::to_string(chunk_id);
        std::string encrypted_name = CryptoUtils::encryptName(plain_name, m_sessionKey);

        Name i3_name(m_gatewayName);
        i3_name.append("fetch").append(encrypted_name);

        Interest i3(i3_name);
        i3.setMustBeFresh(true);
        i3.setInterestLifetime(time::milliseconds(200));

        metrics_tx_i++;
        if (attempt == 1) {
            logPrint("[Producer] Expressing Interest for chunk " + std::to_string(chunk_id));
        } else {
            logPrint("[Producer] Expressing Interest for chunk " + std::to_string(chunk_id) + " (Attempt " + std::to_string(attempt) + "/" + std::to_string(m_maxRetries) + ")");
        }

        m_face.expressInterest(i3,
            [this, chunk_id](const Interest&, const Data& d3) {
                metrics_rx_d++;
                std::string d3_encrypted(reinterpret_cast<const char*>(d3.getContent().value()), d3.getContent().value_size());
                std::string d3_content;
                try {
                    d3_content = CryptoUtils::decryptName(d3_encrypted, m_sessionKey);
                } catch (...) {
                    logPrint("[Producer] Security Error: Decryption failed for D_3 chunk " + std::to_string(chunk_id));
                    return;
                }
                json d3_payload = json::parse(d3_content);
                std::string actual_data = d3_payload["data"];
                logPrint("[Producer] Received Data for chunk " + std::to_string(chunk_id) + ": " + actual_data);
                
                m_successCount++;
                onTaskComplete();
            },
            [this, chunk_id, attempt](const Interest&, const lp::Nack& nack) {
                logPrint("[Producer] Failed to fetch chunk " + std::to_string(chunk_id) + ": Nack on attempt " + std::to_string(attempt));
                retryOrGiveUp(chunk_id, attempt);
            },
            [this, chunk_id, attempt](const Interest&) {
                logPrint("[Producer] Failed to fetch chunk " + std::to_string(chunk_id) + ": Timeout on attempt " + std::to_string(attempt));
                retryOrGiveUp(chunk_id, attempt);
            }
        );
    }

    void retryOrGiveUp(int chunk_id, int attempt) {
        if (attempt < m_maxRetries) {
            fetchSingleChunk(chunk_id, attempt + 1);
        } else {
            logPrint("[Producer] Gave up on chunk " + std::to_string(chunk_id) + " after " + std::to_string(m_maxRetries) + " attempts.");
            onTaskComplete();
        }
    }

    void onTaskComplete() {
        m_activeTasks--;

        if (m_nextChunkId <= m_chunkSize) {
            fetchSingleChunk(m_nextChunkId++);
        } else if (m_activeTasks == 0) {
            auto now = std::chrono::system_clock::now().time_since_epoch();
            double end_time = std::chrono::duration<double>(now).count();
            double completion_time = end_time - m_startTime;

            m_scheduler.schedule(time::milliseconds(500), [this, completion_time] {
                std::cout << "\n=== [EVALUATION] Pipeline Complete ===" << std::endl;
                std::cout << "Chunks Received: " << m_successCount << "/" << m_chunkSize << std::endl;
                std::cout << "Upload Completion Time: " << std::fixed << std::setprecision(4) 
                          << completion_time << " seconds (" << (completion_time * 1000.0) << " ms)" << std::endl;
                std::cout << "Producer Metrics: Total " << (metrics_rx_i + metrics_tx_i + metrics_tx_d + metrics_rx_d)
                          << " {'rx_i': " << metrics_rx_i << ", 'tx_i': " << metrics_tx_i
                          << ", 'tx_d': " << metrics_tx_d << ", 'rx_d': " << metrics_rx_d << "}" << std::endl;
                
                m_face.getIoContext().stop();
            });
        }
    }

    void onRegisterSuccess(const Name& prefix) {}
    void onRegisterFailed(const Name& prefix, const std::string& reason) {
        logPrint("[Producer] Failed to register prefix: " + reason);
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

    int metrics_rx_i = 0;
    int metrics_tx_i = 0;
    int metrics_tx_d = 0;
    int metrics_rx_d = 0;

    int m_windowSize = 4;
    int m_maxRetries = 20;

    std::string m_gatewayName;
    std::string m_sessionId;
    int m_chunkSize;
    std::string m_sessionKey;
    double m_startTime;

    int m_successCount = 0;
    int m_nextChunkId = 1;
    int m_activeTasks = 0;
};

int main() {
    try {
        Producer app;
        app.run();
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}
