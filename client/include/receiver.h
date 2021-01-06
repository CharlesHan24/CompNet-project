#ifndef _RECEIVER_H
#define _RECEIVER_H

#include "host.h"
#include "header.h"
#include <cstdio>
#include <stdint.h>
#include <netinet/in.h>

struct defense_receiver: public defense_host_t{
    sockaddr_in addr_send, addr_recv;

    int sock_addr_len;
    uint32_t sock_fd, self_ip, peer_ip;
    uint16_t peer_port, self_port;

    FILE* log_stream;

    defense_receiver ();
    defense_receiver(uint32_t _self_ip, uint16_t _self_port, uint32_t _pid, char* log_file = NULL);

    void receive();

    ~defense_receiver();
};

#endif