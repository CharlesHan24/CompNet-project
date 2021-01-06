/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;
const bit<8> TYPE_ICMP = 1;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<16> length;
	bit<16> checksum;
}

header int_pid_t{
    bit<32> pid;
}

header cpu_t{
    bit<32> old_pid;
    bit<32> buc_id;
    bit<32> hash_id;
    bit<32> err_type;
}

struct metadata {
    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;
    
    bit<32> pid;
    bit<16> ipv4_srcPort;
    bit<16> ipv4_dstPort;
    bit<32> srcIP;
    bit<32> dstIP;

    bit<32> hash_id;
    bit<32> hash_buc_key;
    bit<32> hash_fingprint;
    bit<48> hash_ts;
    bit<1> existence;
    bit<32> hash_pid;

    bit<32> err_type;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
	udp_t        udp;
    int_pid_t    int_hdr;
    cpu_t        CPU;
}

