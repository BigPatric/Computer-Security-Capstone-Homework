#include <iostream>
#include <cstdlib>
#include <ctime>
#include <string>
#include <cstdio>
#include <thread>
#include <vector>
#include <mutex>
#include <stdint.h>

std::mutex print_mutex;
class GlibcRand {
private:
    uint32_t state[31];
    int front = 3;
    int rear = 0;

public:
    void srand(uint32_t seed) {
        if (seed == 0) seed = 1; // glibc 保護機制
        state[0] = seed;
        for (int i = 1; i < 31; i++) {
            int64_t val = (16807LL * state[i - 1]) % 2147483647;
            if (val < 0) val += 2147483647;
            state[i] = (uint32_t)val;
        }
        front = 3;
        rear = 0;
        for (int i = 0; i < 310; i++) this->rand();
    }

    int rand() {
        uint32_t val = state[front] + state[rear];
        state[front] = val;
        front = (front + 1) % 31;
        rear = (rear + 1) % 31;
        return (int)(val >> 1);
    }
};
// ==========================================

unsigned int predict_random(time_t target_time) {
    GlibcRand linux_rand;
    
    linux_rand.srand(target_time); 
    
    unsigned int r[100];
    for (int i = 0; i < 100; i++) {
        r[i] = linux_rand.rand() % 32323; 
    }
    for (int i = 1; i < 100; i++) {
        r[i] = r[i] * r[i-1]*r[i-1]*r[i-1] + r[i]*r[i-1]*r[i-1]*3 + r[i]*r[i-1]*2 + r[i];
    }
    return r[99];
}
void attack_thread(time_t base_time, int offset, std::string target_ip, std::string target_port) {
    time_t guess_time = base_time + offset;
    unsigned int predicted_value = predict_random(guess_time);
    
    std::string command = "(echo " + std::to_string(predicted_value) + "; sleep 1) | nc " + target_ip + " " + target_port + " 2>&1";
    
    FILE* fp = popen(command.c_str(), "r");
    std::string server_response = "";
    
    if (fp) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), fp)) {
            server_response += buf;
        }
        pclose(fp);
    }

    std::lock_guard<std::mutex> lock(print_mutex);
    if (server_response.empty()) {
        std::cout << "Server: (無回應或連線失敗)\n";
    } else {
        std::cout << "Server: " << server_response;
    }
    std::cout << "----------------------------------------\n";
}

int main() {
    time_t current_time = time(NULL);
    std::string target_ip = "140.113.207.245";
    std::string target_port = "30171";

    std::vector<std::thread> threads;

    for (int offset = -1; offset <= 5; offset++) {
        threads.push_back(std::thread(attack_thread, current_time, offset, target_ip, target_port));
    }

    // 等待所有執行緒的工作都完成
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    return 0;
}