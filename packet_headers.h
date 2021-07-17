#pragma once

#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H
#include <pcap.h>
#define ETHER_ADDR_LEN 6

struct eth_hdr{
    u_int8_t dmac[ETHER_ADDR_LEN];
    u_int8_t smac[ETHER_ADDR_LEN];
    u_int16_t type;
};

struct ip_hdr{
    u_int8_t ver:4;
    u_int8_t len:4;
    u_int8_t srv_type;
    u_int16_t totlen;
    u_int16_t id;
    u_int16_t offset;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t checksum;
    u_int8_t sip[2];
    u_int8_t dip[2];
};

struct tcp_hdr{
    u_int16_t sport;
    u_int16_t dport;
    u_int32_t seqnum;
    u_int32_t acknum;
    u_int8_t offset:4;
    u_int8_t reserved:3;
    u_int16_t flags:9;
    u_int16_t winsize;
    u_int16_t checksum;
};

#endif // PACKET_HEADERS_H
