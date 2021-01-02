#include <map>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <fstream>

#include <unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <sched.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <algorithm>
#include <ctime>
#include <cmath>
#include <mutex>
#include <thread>

#include "receiver.h"
#include "sender.h"

using namespace std;

#define MAX_HOST_CNT 50
#define MAX_STR_LEN 200
#define BASE_PORT_NUM 20000

#define FLOW_SIZE 100

char host_name[MAX_HOST_CNT][MAX_STR_LEN];
uint32_t mnet_host_pid[MAX_HOST_CNT];
char host_ip[MAX_HOST_CNT][MAX_STR_LEN];
uint32_t host_ip_uint[MAX_HOST_CNT];
uint16_t host_port[MAX_HOST_CNT][2];

int config_loader(){
	if (system("sudo bash ./config.sh") != 0) {
		return -1;
	}

	FILE* config = fopen("host.config", "r");
	int tot_host = 0;
	while (fscanf(config, "%s%u%s", host_name[tot_host], &mnet_host_pid[tot_host], host_ip[tot_host]) != EOF){
		tot_host++;
	}

	printf("Tot Host: %d\n", tot_host);
	for (int i = 0; i < tot_host; i++){
		printf("Host_id: %d, Host_name: %s, Host_mnet_pid: %u, Host_ip: %s\n", i, host_name[i], mnet_host_pid[i], host_ip[i]);
	}

	for (int i = 0; i < tot_host; i++){
		host_ip_uint[i] = inet_addr(host_ip[i]);
	}

	return tot_host;
}

defense_sender* senders[MAX_HOST_CNT];
defense_receiver* receivers[MAX_HOST_CNT];

int main(int argc, char* argv[]){
	if (argc != 2){
		printf("Usage: sudo ./traffic <client_cnt>\n");
		return 0;
	}
	
	int client_cnt = atoi(argv[1]);

	int tot_host = config_loader();
	if (tot_host < client_cnt + 1){
		printf("Error: hosts built by mininet not enough\n");
		return 0;
	}

	for (int i = 0; i < tot_host; i++){
		host_port[i][0] = host_port[i][1] = BASE_PORT_NUM + i;
	}

	for (int i = 0; i < client_cnt; i++){
		char log_file[200];
		sprintf(log_file, "/media/data/home/charleshan/CompNet-project/client/bin/log_sender_%d.txt", i);
		senders[i] = new defense_sender(host_ip_uint[client_cnt], host_ip_uint[i], host_port[i][1], host_port[i][0], mnet_host_pid[i], log_file);

		sprintf(log_file, "/media/data/home/charleshan/CompNet-project/client/bin/log_receiver_%d.txt", i);
		receivers[i] = new defense_receiver(host_ip_uint[client_cnt], host_port[i][1], mnet_host_pid[client_cnt], log_file);
	}

	for (int i = 0; i < client_cnt; i++){
		thread cur_thread(&defense_receiver::receive, receivers[i], FLOW_SIZE);
		cur_thread.detach();
	}
	sleep(1);

	for (int i = 0; i < client_cnt; i++){
		thread cur_thread(&defense_sender::send, senders[i], FLOW_SIZE);
		cur_thread.detach();
	}

	sleep(1000);

	return 0;
}