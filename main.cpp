#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#define MAC_LENGTH 6
#define IPV4_LENGTH 4

struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

void process_packet(unsigned char*);
void print_ip_header(unsigned char*);
void print_arp_packet(unsigned char* Buffer);

FILE *logfile;
struct sockaddr_in source,dest;
int arp = 0;

int main() {
    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *)malloc(65536);
    logfile = stdout;

    printf("Starting...\n");
    int sock_raw = socket(AF_PACKET , SOCK_RAW, htons(ETH_P_ARP));

    if (sock_raw < 0) {
        perror("Socket Error");
        return 1;
    } else {
        while (2 + 2 == 4) {
            saddr_size = sizeof saddr;
            data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, (socklen_t *) &saddr_size);
            if (data_size < 0) {
                return 1;
            } else {
                process_packet(buffer);
            }
        }
    }
}

void process_packet(unsigned char* buffer) {
    ++arp;
    print_arp_packet(buffer);
}

void print_mac_address(unsigned char mac[], std::string msg) {
    fprintf(stdout, "   |-%s : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", msg.c_str(), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_address(unsigned char ip[], std::string msg) {
    fprintf(stdout, "   |-%s : %u.%u.%u.%u \n", msg.c_str(), ip[0], ip[1], ip[2], ip[3]);
}

void print_ethernet_header(unsigned char* Buffer) {
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    fprintf(stdout , "\nEthernet Header\n");
    print_mac_address(eth->h_dest, "Destination Address");
    print_mac_address(eth->h_source, "Source Address     ");
    fprintf(stdout , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer) {
    print_ethernet_header(Buffer);
    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile, "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile, "   |-Identification    : %d\n",ntohs(iph->id));
    fprintf(logfile, "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile, "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile, "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile, "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile, "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

bool is_equals(const std::string& a, const std::string& b) {
    return std::equal(a.begin(), a.end(),
                      b.begin(), b.end(),
                      [](char a, char b) {
                          return tolower(a) == tolower(b);
                      });
}

std::string find_company_name_by_mac(unsigned char mac[MAC_LENGTH]) {
    std::ifstream oui("oui.txt");
    std::string line;
    std::stringstream stream;
    char oldFill = stream.fill('0');
    for (int i = 0; i < 3; i++) {
        stream << std::setw(2) << std::hex << static_cast<int>(mac[i]);
    }
    stream.fill(oldFill);

    std::string input(stream.str());
    if (oui.is_open()) {
        while (!oui.eof()) {
            std::getline(oui, line);
            std::string temp = line.substr(0, 6);
            if (is_equals(temp,input)) {
                break;
            }
        }
    }
    return line.size() ? line.substr(22) : "random mac-address";
}

void print_arp_packet(unsigned char* Buffer) {
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    arp_header* arph = (struct arp_header *)(Buffer + iphdrlen + sizeof(struct ethhdr));

    fprintf(logfile , "\n\n***********************ARP Packet*************************\n");

    print_ip_header(Buffer);

    fprintf(logfile , "\n");
    fprintf(logfile , "ARP Header\n");
    fprintf(logfile, "   |-HW Address type : %u\n", ntohs(arph->hardware_type));
    fprintf(logfile, "   |-Protocol Address type : %u\n", ntohs(arph->protocol_type));
    fprintf(logfile, "   |-HW Address length : %u\n", ntohs(arph->hardware_len));
    fprintf(logfile, "   |-Protocol address length : %u\n", ntohs(arph->protocol_len));
    fprintf(logfile, "   |-Operation : %u\n", ntohs(arph->opcode));
    print_ip_address(arph->sender_ip, "Sender IP");
    print_mac_address(arph->sender_mac, "Sender MAC");
    fprintf(logfile, "   |-Sender MAC company: %s\n", find_company_name_by_mac(arph->sender_mac).c_str());
    print_ip_address(arph->target_ip, "Receiver IP");
    print_mac_address(arph->target_mac, "Self MAC");
    fprintf(logfile, "   |-Self MAC company:  %s\n", find_company_name_by_mac(arph->target_mac).c_str());

    fprintf(logfile , "\n###########################################################");
}