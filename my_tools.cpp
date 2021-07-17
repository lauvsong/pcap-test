#include "my_tools.h"

Result res;

bool get_mac(struct libnet_ethernet_hdr* hdr){
    u_int16_t eth_type = ntohs(hdr->ether_type);
    if (eth_type != ETHERTYPE_IP) return false;
    res.dmac = hdr->ether_dhost;
    res.smac = hdr->ether_shost;
    return true;
}

bool get_ip(struct libnet_ipv4_hdr* hdr){
    if (hdr->ip_p != IPPROTO_TCP) return false;
    res.dip = inet_ntoa(hdr->ip_dst);
    res.sip = inet_ntoa(hdr->ip_src);
    return true;
}

void get_port(struct libnet_tcp_hdr* hdr){
    res.dport = hdr->th_dport;
    res.sport = hdr->th_sport;
    return;
}

void print_mac(){
    printf("# ETHERNET\n");
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           res.smac[0], res.smac[1], res.smac[2], res.smac[3], res.smac[4], res.smac[5]);
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
           res.dmac[0], res.dmac[1], res.dmac[2], res.dmac[3], res.dmac[4], res.dmac[5]);
}

void print_ip(){
    printf("# IP\n");
    printf("Src IP: %s\n", res.sip);
    printf("Dst IP: %s\n\n", res.dip);
}

void print_port(){
    printf("# TCP\n");
    printf("Src Port: %d\n", res.sport);
    printf("Dst Port: %d\n\n", res.dport);
}

void print_payload(){
    printf("# PAYLOAD\n");
    for (int i=0;i<8;i++)
        printf("%02x", res.payload[i]);
}

void print_result(){
    print_mac();
    print_ip();
    print_port();
    print_payload();
}

void cature_tcp(const u_char* packet){
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*) packet;
    if(!get_mac(eth_hdr)) return;   // not TCP

    packet += sizeof(struct libnet_ethernet_hdr);
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*) packet;
    if (!get_ip(ip_hdr)) return;    // not TCP

    packet += sizeof(struct libnet_ipv4_hdr);
    struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*) packet;
    get_port(tcp_hdr);

    res.payload = packet + static_cast<u_int8_t>(tcp_hdr->th_off);

    print_result();
    printf("\n---\n");
    return;
}
