#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

    printf("Ethernet Header\n");
    printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("\nIP Header\n");
    printf("src ip: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("dst ip: %s\n", inet_ntoa(ip->iph_destip));

    printf("\nTCP Header\n");
    printf("src port: %d\n", ntohs(tcp->tcp_sport));
    printf("dst port: %d\n", ntohs(tcp->tcp_dport));

    int ip_header_len = ip->iph_ihl * 4; // IP 헤더 길이
    int tcp_header_len = TH_OFF(tcp) * 4; // TCP 헤더 길이 
    const char *payload = (const char *)tcp + tcp_header_len;
    int total_len = ntohs(ip->iph_len);
    int payload_len = total_len - ip_header_len - tcp_header_len;
    if (payload_len > 0) {
        printf("\nHTTP Message\n");
        printf("%.*s\n", payload_len, payload);
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    // PCAP_ERRBUF_SIZE: pcap 라이브러리에서 발생하는 오류 메시지를 저장하는 버퍼의 최대 크기
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}