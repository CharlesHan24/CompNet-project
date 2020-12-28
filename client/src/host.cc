#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
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

#include "header.h"
#include "host.h"

#define MAX_PATH_LENGTH 200

defense_host_t::defense_host_t () {}

defense_host_t::defense_host_t (uint32_t pid) {
    switch_namespace(pid);
}

void defense_host_t::switch_namespace(uint32_t pid) {
    char path[MAX_PATH_LENGTH];

    sprintf(path, "/proc/%u/ns/net", pid);
    int status_net = attachToNS(path);
    // printf("attach net: %d.\n", status_net);

    sprintf(path, "/proc/%u/ns/pid", pid);
    int status_pid = attachToNS(path);
    // printf("attach pid: %d.\n", status_pid);

    sprintf(path, "/proc/%u/ns/mnt", pid);
    int status_mnt = attachToNS(path);
    // printf("attach mnt: %d.\n", status_mnt);

    // if (system("ifconfig | grep inet") != 0) {
    // 	exit(0);
    // }
}

int defense_host_t::attachToNS(char* path) {
    int nsid = open(path, O_RDONLY);
    return setns(nsid, 0);
}
