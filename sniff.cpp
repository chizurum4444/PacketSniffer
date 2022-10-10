#include <iostream>
#include <pcap.h>
#include <pcap/bpf.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

// If you are on linux use:
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>


// Function to handle incoming packets.
void packet_handler(u_char *user_data, 
    const struct pcap_pkthdr* packet_header, 
    const u_char* packet) {
    
    const struct ether_header* ether;
    ether = (struct ether_header*) packet;
    auto type = ntohs(ether->ether_type);

    
    // see if this is an IPv4 frame
    if (type == ETHERTYPE_IP) {
        struct ip* ip_header;
        ip_header = (struct ip*) (packet + 14);
        
        if (ip_header->ip_p == IPPROTO_UDP) {
            // u_int16_t uh_sport;              
            // u_int16_t uh_dport;
            std::cout << "Packet is udp!" << std::endl;

            auto header_length = ip_header->ip_hl * 4;
            auto payload = (u_char*) (packet + header_length + 14);

            struct udphdr *udp = (struct udphdr*)(payload);
            struct servent* service = getservbyport(udp->uh_dport, "udp");

            auto udp_src = ntohs(udp->uh_sport);
            std::cout << "  Source port: " << (udp_src) << std::endl;

            auto udp_dst = ntohs(udp->uh_dport);
            std::cout << "  Destination port: " << (udp_dst) << std::endl;

            if(service != NULL){
                if(udp_src < 1024){
                    std::cout<<"    Service name: "<< service->s_name <<std::endl;
                }else if(udp_dst < 1024){
                    std::cout<<"    Service name: "<< service->s_name <<std::endl;
                }  
            }

            auto addr = (char*) &(ip_header->ip_src);
            printf("  Source address: %hhu.%hhu.%hhu.%hhu\n",addr[0], addr[1],addr[2], addr[3]);

            auto addr2 = (char*) &(ip_header->ip_dst);
            printf("  Destination address: %hhu.%hhu.%hhu.%hhu\n",addr2[0], addr2[1],addr2[2], addr2[3]);

            std::cout << "  header length " << header_length << std::endl;

        } else if (ip_header->ip_p == IPPROTO_TCP) {
            // u_short th_sport;   /* source port */
            // u_short th_dport;   /* destination port */
            // u_int32_t th_seq;       /* sequence number */
            // u_int32_t th_ack;       /* acknowledgement number */

            std::cout << "Packet is tcp!" << std::endl;

            auto header_length = ip_header->ip_hl * 4;
            auto payload = (u_char*) (packet + header_length + 14);  
            struct tcphdr *tcp = (struct tcphdr*)(payload);
            struct servent* service = getservbyport(tcp->th_dport, "tcp");
            
            
            auto addr1 = ntohs(tcp->th_sport);
            std::cout << "  Source port: " << (addr1) << std::endl;

            auto addr2 = ntohs(tcp->th_dport);
            std::cout << "  Destination port: " << (addr2) << std::endl;
    
    
            if(service != NULL){
                if(addr1 < 1024){
                    std::cout<<"    Service name: "<< service->s_name <<std::endl;
                }else if(addr2 < 1024){
                    std::cout<<"    Service name: "<< service->s_name <<std::endl;
                }
            }

            auto addr3 = (tcp->th_seq);
            std::cout << "  Sequence number: " << ntohl(addr3) << std::endl;

            auto addr4 = (tcp->th_ack);
            std::cout << "  Acknowledgment number: " << ntohl(addr4) << std::endl;


            if ((tcp->th_flags&TH_ACK) != 0) {
                std::cout << "  ACK flag is set !"<< std::endl;
            }

            if ((tcp->th_flags&TH_SYN) != 0) {
                std::cout << "  SYN flag is set !"<< std::endl;
            }

            if ((tcp->th_flags&TH_FIN) != 0) {
                std::cout << "  FIN flag is set !"<< std::endl;
            }

            if ((tcp->th_flags&TH_RST) != 0) {
                std::cout << "  RST flag is set !"<< std::endl;
            }

            auto addr = (char*) &(ip_header->ip_src);
            printf("  Source address: %hhu.%hhu.%hhu.%hhu\n",addr[0], addr[1],addr[2], addr[3]);

            addr = (char*) &(ip_header->ip_dst);
            printf("  Destination address: %hhu.%hhu.%hhu.%hhu\n",addr[0], addr[1],addr[2], addr[3]);

            std::cout << "  header length " << header_length << std::endl;

        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            // will get us ping packets

            std::cout << "Packet is ICMP!" << std::endl;
            auto header_length = ip_header->ip_hl * 4;
            auto payload = (u_char*) (packet + header_length + 14);
            struct icmp *icmp = (struct icmp*) (payload);
            auto type = ntohs(icmp->icmp_type);
            auto type2 = (icmp->icmp_code);

            if(type ==  ICMP_ECHO){
                printf("    Packet type: %d\n ",(int)type);
            }else if(type ==ICMP_ECHOREPLY){
                printf("    Packet type: %d\n ",(int)type);
            }else if(type ==  ICMP_UNREACH){
                printf("    Packet type: %d\n ",(int)type);
                printf("    Code: %d\n ",(int)type2);
            }
        }

    }
}

int main(int argv, char** args) {
    char errbuf[PCAP_BUF_SIZE]; // initialize and empty string for errors
    pcap_if_t* first_device;
    
    pcap_findalldevs(&first_device, errbuf);
    if (first_device == NULL) {
        std::cerr << "couldn't find a device" << errbuf << std::endl;
    }

    for (auto current_device = first_device; current_device; current_device = current_device->next) {
        std::cout << current_device->name << std::endl;
    }

    // Use this if you have an ethernet device to work with.
    // auto handle = pcap_create("en0", errbuf);

    // Use this code for files:
    auto file = fopen("test.anon", "rb");
    auto handle = pcap_fopen_offline(file, errbuf);


    // Change handler settings

    pcap_set_promisc(handle, PCAP_OPENFLAG_PROMISCUOUS); // set promiscuous mode
    // pcap_set_timeout(handle, 1); // set a timeout
    pcap_set_immediate_mode(handle, 1); // give us packets as soon as they come in
    auto err = pcap_activate(handle); // activate handler

 
    struct bpf_program fp;
    pcap_compile(handle, &fp, "icmp", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);


    pcap_loop(handle, 0, packet_handler, NULL);
}
