#include <iostream>
#include <iomanip>
#include <cstring>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

using namespace std;

struct Device {
    struct in_addr ip;
    uint8_t        mac[6];
};

struct ArpPacket {
    struct ethhdr     eth;
    struct ether_arp  arp;
};


// Retrieve the MAC address for a given interface via an existing socket fd.
static bool get_iface_mac(int sockfd, const char *iface, uint8_t mac[6])
{
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        return false;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

// Retrieve the interface index via an existing socket fd.
// Returns -1 on failure.
static int get_iface_index(int sockfd, const char *iface)
{
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        return -1;
    }

    return ifr.ifr_ifindex;
}

static void print_mac(const uint8_t mac[6])
{
    for (int i = 0; i < 6; ++i) {
        if (i) cout << ':';
        cout << hex << setw(2) << setfill('0') << (int)mac[i];
    }
    cout << dec;
}

// == Main Program ==
int main(int argc, char *argv[])
{
    if (argc < 3) {
        cerr << "Usage: sudo " << argv[0] << " <self_ip> <interface>\n";
        return 1;
    }

    const char *self_ip_str = argv[1];
    const char *iface       = argv[2];

    // Parse self IP and derive /24 subnet base
    uint32_t ip_net    = inet_addr(self_ip_str);          // network byte order
    uint32_t ip_host   = ntohl(ip_net);                   // host byte order
    uint32_t subnet    = ip_host & 0xFFFFFF00u;

    // Open raw ARP socket 
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("socket() — try running with sudo");
        return 1;
    }

    //  Resolve interface info (reuse sockfd — no temp socket needed) 
    uint8_t self_mac[6];
    if (!get_iface_mac(sockfd, iface, self_mac)) {
        cerr << "Failed to get MAC for interface: " << iface << '\n';
        close(sockfd);
        return 1;
    }

    int if_index = get_iface_index(sockfd, iface);
    if (if_index < 0) {
        cerr << "Failed to get index for interface: " << iface << '\n';
        close(sockfd);
        return 1;
    }

    //  Receive timeout so we don't block forever 
    struct timeval tv{ .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    //  Build the ARP request template 
    ArpPacket req{};

    // Ethernet header
    memset(req.eth.h_dest,   0xff,      6);
    memcpy(req.eth.h_source, self_mac,  6);
    req.eth.h_proto = htons(ETH_P_ARP);

    // ARP header (fields that never change across the sweep)
    req.arp.arp_hrd = htons(ARPHRD_ETHER);
    req.arp.arp_pro = htons(ETH_P_IP);
    req.arp.arp_hln = 6;
    req.arp.arp_pln = 4;
    req.arp.arp_op  = htons(ARPOP_REQUEST);
    memcpy(req.arp.arp_sha, self_mac, 6);
    memcpy(req.arp.arp_spa, &ip_net,  4);
    memset(req.arp.arp_tha, 0x00,     6);

    // Destination address for sendto()
    struct sockaddr_ll dest{};
    dest.sll_family  = AF_PACKET;
    dest.sll_ifindex = if_index;
    dest.sll_halen   = 6;
    memset(dest.sll_addr, 0xff, 6);

    for (int i = 1; i < 255; ++i) {
        uint32_t target = htonl(subnet | (uint32_t)i);
        memcpy(req.arp.arp_tpa, &target, 4);
        sendto(sockfd, &req, sizeof req, 0,
               reinterpret_cast<sockaddr*>(&dest), sizeof dest);
    }

    //  Collect replies 
    static Device devices[256];
    int           device_count = 0;

    ArpPacket resp;
    while (recv(sockfd, &resp, sizeof resp, 0) > 0) {

        if (ntohs(resp.eth.h_proto) != ETH_P_ARP  ||
            ntohs(resp.arp.arp_op)  != ARPOP_REPLY)
            continue;

        struct in_addr sender_ip;
        memcpy(&sender_ip, resp.arp.arp_spa, 4);

        // Skip ourselves
        if (sender_ip.s_addr == ip_net) continue;

        // Skip duplicates
        bool exists = false;
        for (int j = 0; j < device_count; ++j) {
            if (devices[j].ip.s_addr == sender_ip.s_addr) { exists = true; break; }
        }
        if (exists || device_count >= 256) continue;

        devices[device_count].ip = sender_ip;
        memcpy(devices[device_count].mac, resp.arp.arp_sha, 6);
        ++device_count;
    }

    close(sockfd);

    // ── Print results ────────────────────────────────────────────────────────
    const char *line = "--------------------------------------------";
    cout << '\n' << line << '\n'
        << left << setw(8) << "Index" << right << "| "
        << left << setw(15) << "IP" << right << "| "
        << left << setw(17) << "MAC" << right << '\n'
        << line << '\n';

    for (int i = 0; i < device_count; ++i) {
        cout << i << "       | "
            << left << setw(15) << inet_ntoa(devices[i].ip) << right << "| ";
        print_mac(devices[i].mac);
        cout << '\n';
    }

    cout << line << '\n';
    return 0;
}