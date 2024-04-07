#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

struct ethheader {
    u_char ether_dhost[6];
    u_char ether_shost[6]; 
    u_short ether_type; 
};

struct ipheader {
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos; 
    unsigned short int iph_len;
    unsigned short int iph_flag : 3, iph_offset : 13; 
    unsigned char iph_ttl; 
    unsigned char iph_protocol; 
    struct in_addr iph_sourceip;
    struct in_addr iph_destip; 
};

struct tcpheader { 
    u_short tcp_sport; 
    u_short tcp_dport; 
    u_int tcp_seq; 
    u_int tcp_ack; 
    u_char tcp_offx2; 
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS(TH_FLAGS) (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win; // window
    u_short tcp_sum; // checksum
    u_short tcp_urp; // urgent pointer
};

struct pseudo_tcp {
    unsigned saddr, daddr; 
    unsigned char mbz; 
    unsigned char ptcl; 
    unsigned short tcpl;
    struct tcpheader tcp;
    char payload[1500];
};

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ethheader* eth = (struct ethheader*)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader* ip = (struct ipheader*) (packet + sizeof(struct ethheader));

        printf("     From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("    To: %s\n", inet_ntoa(ip->iph_destip));

        printf(" Source MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf(" Destination MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
            
            printf(" Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf(" Destination Port: %d\n", ntohs(tcp->tcp_dport));
        }
        
        switch (ip->iph_protocol) { 
        case IPPROTO_TCP:
            printf("    Protocol: TCP\n\n");
            return;
        case IPPROTO_UDP:
            printf("    Protocol: UDP\n\n");
            return;
        case IPPROTO_ICMP:
            printf("    Protocol: ICMP\n\n");
            return;
        default:
            printf("    Protocol: others\n\n");
            return;
        }
    }
}

int main() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp"; 
    bpf_u_int32 net;
    
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE); 
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
