#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h> // inet_ntoa()
#include <netinet/ip.h> // IP Header Structure
#include <netinet/tcp.h> // TCP Header Structure
#include <netinet/ether.h> // ehter_ntoa()
#include <netinet/if_ether.h> // Ethernet Header Structure

struct ip *ip_header;
struct tcphdr *tcp_header;
struct ether_header *ethernet_header;

uint16_t ether_type;

int main(int argc, char* argv[]) {
    
    if (argc != 2) return -1;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        printf("handle을 열 수 없음...\n");
        return -1;
    }

    while (true) { // 패킷을 계속 수신함.
        struct pcap_pkthdr* header;
        const u_char* packet;
        // header에는 패킷의 메타데이터(타임 스탬프, 잡힌 패킷 크기 등...)가, 실제 패킷의 시작은 packet에 저장.
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) { // 예외처리...
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        // 여기다가 패킷 정보(src ip, dest ip 등)를 출력
        printf("%u bytes captured\n\n", header->caplen);

        ethernet_header = (ether_header*)packet;
        ether_type = ntohs(ethernet_header->ether_type);

        printf("1. Ethernet Header\n");

        printf("Source MAC : %s\n", ether_ntoa((ether_addr*)ethernet_header->ether_shost));
        printf("Destination MAC : %s\n", ether_ntoa((ether_addr*)ethernet_header->ether_dhost));

        printf("\n");

        if (ether_type == ETHERTYPE_IP) { // IP Packet
            packet += sizeof(ether_header); // IP Packet을 가져오기 위해... Ethernet Packet size 더해주기...

            ip_header = (ip*)packet;

            printf("2. IP Header\n");
            printf("Source IP : %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP : %s\n", inet_ntoa(ip_header->ip_dst));
            printf("\n");

            if (ip_header->ip_p == IPPROTO_TCP) { // TCP Packet
                unsigned int ip_hsize = ip_header->ip_hl * 4; // TCP Packet을 가져오기 위해... IP Header Size * 4 더해주기...
                packet += ip_hsize;
                tcp_header = (tcphdr*)(packet);

                printf("3. TCP Header\n");
                printf("Source Port : %d\n", ntohs(tcp_header->source));
                printf("Destination Port : %d\n", ntohs(tcp_header->dest));
                printf("\n");

                unsigned int tcp_hsize = tcp_header->th_off * 4;
                unsigned int packet_size = header->caplen;
                unsigned int ether_ip_tcp_size = 14 + ip_hsize + tcp_hsize;
                if (packet_size > ether_ip_tcp_size) { // Ethernet + IP + TCP Header의 길이가 전체 패킷의 길이보다 길다면... Payload가 존재한다...?
                    packet += tcp_hsize;
                    unsigned int payload_size = packet_size - ether_ip_tcp_size;
                    printf("4. Payload\n");
                    unsigned int cnt = payload_size >= 16 ? 16 : payload_size;
                    while (cnt--) {
                        printf("%02x ", *(packet++));
                    }
                    printf("\n");
                }
            }
        }
        printf("---------------\n");
    }

    pcap_close(handle);

    return 0;
}