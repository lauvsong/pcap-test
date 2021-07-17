#pragma once

#include <pcap.h>
#include <libnet.h>
#include <stdbool.h>
#include <arpa/inet.h>

typedef struct {
    u_int8_t* dmac;
    u_int8_t* smac;
    char* dip;
    char* sip;
    u_int16_t dport;
    u_int16_t sport;
    const u_char* payload;
} Result;

bool get_mac(struct libnet_ethernet_hdr*);
bool get_ip(struct libnet_ipv4_hdr*);
void get_port(struct libnet_tcp_hdr*);

void print_mac();
void print_ip();
void print_port();
void print_payload();
void print_result();

void cature_tcp(const u_char* packet);
