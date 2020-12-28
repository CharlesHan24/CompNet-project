#ifndef _HEADER_H
#define _HEADER_H

#include <unistd.h>
#include <stdint.h>

#define PAYLOAD_LEN 104
struct payload_t{
    uint32_t packet_id;
    uint8_t payload[PAYLOAD_LEN];
};

struct int_header_t{
    uint32_t pid;
};


struct ipv4_addr{
    uint8_t addr[4];
};

typedef ipv4_addr ipv4_addr_t;

struct __attribute__((packed)) ipv4_hdr_t{
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t ident;
    uint16_t flags;
    uint8_t ttl;
    uint8_t proto;
    uint16_t hdr_csum;
    ipv4_addr_t src;
    ipv4_addr_t dst;
};

struct __attribute__((packed)) app_packet_t{
    int_header_t int_header;
    payload_t buf;
};



#endif