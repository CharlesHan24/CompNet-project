#include "host.h"
#include "header.h"
#include "sender.h"

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <thread>
#include <syscall.h>
#include <fcntl.h>
#include <sched.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>



defense_sender::defense_sender () {}

defense_sender::defense_sender(uint32_t _peer_ip, uint32_t _self_ip, uint16_t _peer_port, uint16_t _self_port, uint32_t _pid, char* log_file = NULL): defense_host_t(_pid){
	peer_ip = _peer_ip;
	self_ip = _self_ip;
	peer_port = _peer_port;
	self_port = _self_port;

	log_stream = NULL;
	if (log_file != NULL){
		log_stream = fopen(log_file, "w");
		if (log_stream == NULL){
			printf("Sender: Failed to open log file\n");
			exit(1);
		}
	}
	
	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock_fd < 0) {
		printf("Sender: Failed to create socket.\n");
		exit(1);
	}

	// printf("ip: %s, port: %d\n", recv_ip.c_str(), recv_port);

	sock_addr_len = sizeof(sockaddr_in);

	memset((char *)&addr_recv, 0, sock_addr_len);
	memset((char*)&addr_send, 0, sock_addr_len);

	addr_recv.sin_family = AF_INET;
	addr_recv.sin_addr.s_addr = peer_ip;
	addr_recv.sin_port = htons(peer_port);

	addr_send.sin_family = AF_INET;
	addr_send.sin_addr.s_addr = self_ip;
	addr_send.sin_port = htons(self_port);
	if (bind(sock_fd, (sockaddr*)&addr_send, sock_addr_len) < 0) {
        printf("Sender: Bind error.\n");
        exit(1);
    }
	
	printf("Sender: Successfully create the socket. sender: (%s, %hu), receiver: (%s, %hu)\n", 
		inet_ntoa((in_addr){.s_addr=self_ip}), self_port, inet_ntoa(addr_recv.sin_addr), peer_port);
	if (log_stream != NULL){
		fprintf(log_stream, "Sender: Successfully create the socket. sender: (%s, %hu), receiver: (%s, %hu)\n", 
			inet_ntoa((in_addr){.s_addr=self_ip}), self_port, inet_ntoa(addr_recv.sin_addr), peer_port);
	}
}

void defense_sender::send(int packet_cnt){
	app_packet_t packet;

	printf("Packet_cnt: %d\n", packet_cnt);
	
	for (int i = 0; i < PAYLOAD_LEN; i++){
		packet.buf.payload[i] = (i % 26) + 'a';
	}
	for (int sendp = 0; sendp < packet_cnt; sendp++) {
		packet.int_header.pid = htonl(getpid());
		packet.buf.packet_id = htonl(sendp);
		int send_num = sendto(sock_fd, (void*)&packet, sizeof(app_packet_t),
				0, (sockaddr *)&addr_recv, sock_addr_len);

		

		// printf("send: %d / %d bytes (PKT : %d)\n", send_num, header_len, sendp);
		// printf("recv ip: %s, recv port: %d\n", recv_ip.c_str(), recv_port);

		if (send_num < 0) {
			printf("Sender: failed to send packets\n");
			if (log_stream != NULL){
				fprintf(log_stream, "Sender: failed to send packets\n");
			}
			exit(1);
		}

		printf("Sender: %d / %d packet; self_ip: %s, self_port: %hu\n", sendp + 1, packet_cnt, inet_ntoa((in_addr){.s_addr=self_ip}), self_port);

		if (log_stream != NULL){
			fprintf(log_stream, "Sender: %d / %d packet; self_ip: %s, self_port: %hu\n", sendp + 1, packet_cnt, inet_ntoa((in_addr){.s_addr=self_ip}), self_port);
			fprintf(log_stream, "pid=%d\n", getpid());
		}
		// change to 0.1s
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	printf("Sender: finished\n");
	delete(this);
}

defense_sender::~defense_sender(){
	close(sock_fd);
	if (log_stream != NULL){
		fclose(log_stream);
	}
}
