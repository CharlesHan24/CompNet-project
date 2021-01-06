#include "host.h"
#include "header.h"
#include "receiver.h"

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
#include <netinet/in.h>
#include <arpa/inet.h>

defense_receiver::defense_receiver () {}

defense_receiver::defense_receiver(uint32_t _self_ip, uint16_t _self_port, uint32_t _pid, char* log_file = NULL): defense_host_t(_pid){
    self_ip = _self_ip;
    self_port = _self_port;

    log_stream = NULL;
    if (log_file != NULL){
        log_stream = fopen(log_file, "w");
        if (log_stream == NULL){
            printf("Receiver: Failed to open log file\n");
            exit(1);
        }
    }

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock_fd < 0) {
        printf("Receiver: error creating socket\n");
        exit(1);
    }

    sock_addr_len = sizeof(sockaddr_in);

    memset((char *)&addr_send, 0xff, sock_addr_len);
    memset((char *)&addr_recv, 0, sock_addr_len);

    addr_recv.sin_family = AF_INET;
    addr_recv.sin_addr.s_addr = self_ip;
    addr_recv.sin_port = htons(self_port);

    if (bind(sock_fd, (sockaddr *)&addr_recv, sock_addr_len) < 0) {
        printf("Receiver: Bind error.\n");
        exit(1);
    }

    printf("Receiver: Successfully create the socket. receiver: (%s, %hu)\n", 
        inet_ntoa((in_addr){.s_addr=self_ip}), self_port);
    if (log_stream != NULL){
        fprintf(log_stream, "Receiver: Successfully create the socket. receiver: (%s, %hu)\n", 
            inet_ntoa((in_addr){.s_addr=self_ip}), self_port);
    }
}

void defense_receiver::receive(int packet_cnt){
    app_packet_t packet;
    int addr_len = 16;

    printf("Packet_cnt: %d\n", packet_cnt);

    for (int recvp = 0; recvp < packet_cnt; recvp++){
        int recv_num = recvfrom(sock_fd, (void*)&packet, sizeof(app_packet_t), 0, (sockaddr*)&addr_send, (socklen_t*)&addr_len);

        ipv4_hdr_t* ip_dup = (ipv4_hdr_t*)(&packet.buf);

        if (recv_num != sizeof(app_packet_t)){
            printf("Receiver: failed to receive packets\n");
            if (log_stream != NULL){
                fprintf(log_stream, "Receiver: failed to receive packets\n");
            }
            exit(1);
        }

        /*if (ntohl(packet.buf.packet_id) != recvp){
            printf("Receiver: incorrect packet id\n");
            if (log_stream != NULL){
                fprintf(log_stream, "Receiver: incorrect packet id\n");
            }
            exit(1);
        }*/

        if (!recvp){
            peer_port = ntohs(addr_send.sin_port);
            peer_ip = addr_send.sin_addr.s_addr;
        }

        printf("Receiver:  %d / %d packet; peer_ip: %s, peer_port: %hu\n", recvp + 1, packet_cnt, inet_ntoa((in_addr){.s_addr=peer_ip}), peer_port);

        if (log_stream != NULL){
            fprintf(log_stream, "Receiver:  %d / %d packet; peer_ip: %s, peer_port: %hu, ", recvp + 1, packet_cnt, inet_ntoa((in_addr){.s_addr=peer_ip}), peer_port);
            fprintf(log_stream, "self_ip: %s, self_port:%hu\n", inet_ntoa(addr_recv.sin_addr), self_port);

            fprintf(log_stream, "pid = %d, packet_id = %d\n", ntohl(packet.int_header.pid), ntohl(packet.buf.packet_id));

            fprintf(log_stream, "%s\n", packet.buf.payload);
        }
    }

    printf("Receiver: finished\n");
    delete(this);
}

defense_receiver::~defense_receiver(){
    close(sock_fd);
    if (log_stream != NULL){
        fclose(log_stream);
    }
}