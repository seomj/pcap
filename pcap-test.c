#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

struct data{
    uint8_t data[8];
};

void eth_address();
void ipv4_address();
void tcp_address();
void payload();

void check_tcp(const u_char* packet){
    struct libnet_ethernet_hdr *eth_p;
    eth_p = (struct libnet_ethernet_hdr *)packet;

    struct libnet_ipv4_hdr *ipv4_p;
    ipv4_p = (struct libnet_ipv4_hdr *)(packet+14);

    struct libnet_tcp_hdr *tcp_p;
    tcp_p = (struct libnet_tcp_hdr *)(packet+14+ipv4_p->ip_hl*4);

    struct data *payload_p = (struct data *)(packet+14+(ipv4_p->ip_hl*4)+(tcp_p->th_off*4));

    if(ipv4_p->ip_p == 6){
        eth_address(eth_p);
        ipv4_address(ipv4_p);
        tcp_address(tcp_p);
        payload(payload_p);
    }

}

void eth_address(struct libnet_ethernet_hdr *packet){
    printf("\n=====MAC=====\n");
    printf("dst: ");
    for(int i=0; i < ETHER_ADDR_LEN; i++){
        printf("%02x ", packet->ether_dhost[i]);
    }
    printf("\n");
    printf("src: ");
    for(int i=0; i < ETHER_ADDR_LEN; i++){
        printf("%02x ", packet->ether_shost[i]);
    }

}

void ipv4_address(struct libnet_ipv4_hdr *packet){
    printf("\n=====IPv4=====\n");
    printf("src: ");

    printf("%s ", inet_ntoa(packet->ip_src));

    printf("\n");
    printf("dst: ");

    printf("%s ", inet_ntoa(packet->ip_dst));

    printf("\n");

}

void tcp_address(struct libnet_tcp_hdr *packet){
    printf("\n=====TCP=====\n");
    printf("src: ");

    printf("%d ", ntohs(packet->th_sport));

    printf("\n");
    printf("dst: ");

    printf("%d ", ntohs(packet->th_dport));

    printf("\n");

}

void payload(struct data *packet){
    printf("\n=====DATA=====\n");

    for(int i = 0; i < 8; i++){
        printf("%02x ", packet->data[i]);
    }

    printf("\n");
    printf("\n");

}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        check_tcp(packet);

    }

    pcap_close(pcap);

}
