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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<1>  MIH_fg;
    bit<1>  SFH_fg;
    bit<1>  SFH_sketch_number;
    bit<1>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header int_pid_t{
    bit<32> pid;
}

header cpu_t{
    bit<32> pid;
    bit<16> ipv4_srcPort;
    bit<16> ipv4_dstPort;
    bit<32> srcIP;
    bit<32> dstIP;
}

struct metadata {
    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;
    
    bit<32> pid;
    bit<16> ipv4_srcPort;
    bit<16> ipv4_dstPort;
    bit<32> srcIP;
    bit<32> dstIP;
    bit<32> record_index_hash;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
	udp_t        udp;
    tcp_t        tcp;   
    int_pid_t    int_hdr;
    cpu_t        CPU;
}

