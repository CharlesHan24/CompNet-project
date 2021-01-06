#ifndef _SENDER_H
#define _SENDER_H

#include "host.h"
#include "header.h"
#include <cstdio>
#include <stdint.h>
#include <netinet/in.h>

struct defense_sender: public defense_host_t{
	sockaddr_in addr_recv;
	sockaddr_in addr_send;

	int sock_fd, sock_addr_len;
    uint32_t peer_ip, self_ip;
    uint16_t self_port, peer_port;

    FILE* log_stream;

	defense_sender ();

	defense_sender(uint32_t _peer_ip, uint32_t _self_ip, uint16_t _peer_port, uint16_t _self_port, uint32_t _pid, char* log_file = NULL);

	void send(int packet_cnt, int sleep_interval);

	~defense_sender();
};

#endif