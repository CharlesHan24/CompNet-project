/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);

        meta.srcIP = hdr.ipv4.srcAddr;
        meta.dstIP = hdr.ipv4.dstAddr;

		transition select(hdr.ipv4.protocol) {
			TYPE_UDP : parse_udp;
            TYPE_ICMP: accept;
			default : accept;
		}
    }

    state parse_udp {
        packet.extract(hdr.udp);

		meta.ipv4_srcPort = hdr.udp.srcPort;
		meta.ipv4_dstPort = hdr.udp.dstPort;

        transition parse_int;
    }


    state parse_int{
        packet.extract(hdr.int_hdr);
        meta.pid = hdr.int_hdr.pid;
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);

        packet.emit(hdr.int_hdr);
        packet.emit(hdr.CPU);
        

        // packet.emit(hdr.ethernet);
        // packet.emit(hdr.udp);
        // packet.emit(hdr.int_hdr);
    }
}
