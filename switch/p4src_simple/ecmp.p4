
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "./headers.p4"
#include "./parsers.p4"

#define BUCKET_NUM 20000
#define TIMESTAMP_WIDTH 48
#define FINGPRINT_WIDTH 32
#define PROCID_WIDTH 32

#define PROC_ID_CONFLICT 0x1
#define HASH_COLLISION 0x2
#define NO_ERROR 0x0
#define DELTA_T (bit<48>)60000000    
// timeout value. 6 * 10^7 us = 60s. standard_metadata.ingress_global_timestamp is in microseconds. 

register<bit<TIMESTAMP_WIDTH> >(BUCKET_NUM) last_ts;
register<bit<FINGPRINT_WIDTH> >(BUCKET_NUM) fingprint;
register<bit<1> >(BUCKET_NUM) existence;
register<bit<PROCID_WIDTH> >(BUCKET_NUM) proc_id;

#define COMPUTE_ID_HASH hash(meta.hash_id,\
			 HashAlgorithm.crc32_custom,\
			 (bit<16>)1,\
			 {hdr.ipv4.srcAddr,\
			  hdr.ipv4.dstAddr,\
			  hdr.udp.srcPort,\
			  hdr.udp.dstPort,\
			  hdr.ipv4.protocol},\
			 (bit<32>)0xffff_ffff);



#define COMPUTE_ARRAY_HASH hash(meta.hash_buc_key,\
			 HashAlgorithm.crc32_custom,\
			 (bit<16>)0,\
			 {hdr.ipv4.srcAddr,\
			  hdr.ipv4.dstAddr,\
			  hdr.udp.srcPort,\
			  hdr.udp.dstPort,\
			  hdr.ipv4.protocol},\
			 (bit<32>)BUCKET_NUM);


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta)
{
	apply {}
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
				  inout metadata meta,
				  inout standard_metadata_t standard_metadata)
{

	/******************* inherited code starts here       ************************/
	action drop(){
		mark_to_drop(standard_metadata);
	}

	action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops)
	{
		hash(meta.ecmp_hash,
			HashAlgorithm.crc16,
			(bit<1>)0,
			{hdr.ipv4.srcAddr,
			hdr.ipv4.dstAddr,
			meta.ipv4_srcPort,
			meta.ipv4_dstPort,
			hdr.ipv4.protocol
			},
			num_nhops);
		meta.ecmp_group_id = ecmp_group_id;
	}

	action set_nhop(macAddr_t dstAddr, egressSpec_t port)
	{
		//set the src mac address as the previous dst, this is not correct right?
		hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
		//set the destination mac address that we got from the match in the table
		hdr.ethernet.dstAddr = dstAddr;
		//set the output port that we also get from the table
		standard_metadata.egress_spec = port;
		//decrease ttl by 1
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	table ecmp_group_to_nhop
	{
		key = {
			meta.ecmp_group_id : exact;
			meta.ecmp_hash : exact;
		}
		actions = {
			drop;
			set_nhop;
		}
		size = 1024;
	}

	table ipv4_lpm
	{
		key = {
			hdr.ipv4.dstAddr : lpm;
		}
		actions = {
		    set_nhop;
			ecmp_group;
			drop;
		}
		size = 1024;
		default_action = drop;
	}

	/******************* inherited code ends here       ************************/


	action update_and_filter(){
		COMPUTE_ID_HASH
		COMPUTE_ARRAY_HASH

		existence.read(meta.existence, meta.hash_buc_key);
		fingprint.read(meta.hash_fingprint, meta.hash_buc_key);
		last_ts.read(meta.hash_ts, meta.hash_buc_key);
		proc_id.read(meta.hash_pid, meta.hash_buc_key);
		meta.err_type = NO_ERROR;
		
		if (meta.existence == 0){
			meta.hash_fingprint = meta.hash_id;
			meta.existence = 1;
			meta.hash_ts = standard_metadata.ingress_global_timestamp;
			meta.hash_pid = meta.pid;
		}
		else if (standard_metadata.ingress_global_timestamp - meta.hash_ts > DELTA_T){
			meta.hash_fingprint = meta.hash_id;
			meta.hash_pid = meta.pid;
			meta.hash_ts = standard_metadata.ingress_global_timestamp;
		}
		else{
			if (meta.hash_fingprint == meta.hash_id){
				meta.hash_ts = standard_metadata.ingress_global_timestamp;
				if (meta.pid != meta.hash_pid){
					meta.err_type = PROC_ID_CONFLICT;
				}
				// else do nothing
			}
			else{
				meta.err_type = HASH_COLLISION;
			}
		}
		existence.write(meta.hash_buc_key, meta.existence);
		fingprint.write(meta.hash_buc_key, meta.hash_fingprint);
		last_ts.write(meta.hash_buc_key, meta.hash_ts);
		proc_id.write(meta.hash_buc_key, meta.hash_pid);
	}


	/******** log code starts here*******/


	/******** log code ends here*******/

	apply
	{   
		if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 1) {
			update_and_filter();
			
			switch (ipv4_lpm.apply().action_run){
				ecmp_group:{
					ecmp_group_to_nhop.apply();
				}
			}
		}
		else{
			drop();
		}
	}
	
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
				 inout metadata meta,
				 inout standard_metadata_t standard_metadata)
{
	
	action send_to_control_plane(){
		clone3(CloneType.E2E, 100, meta);
	}

	action drop(){
		mark_to_drop(standard_metadata);
	}

	// action dbg_dup_ipv4(){
	// 	hdr.ip_dup.version = hdr.ipv4.version;
	// 	hdr.ip_dup.ihl = hdr.ipv4.ihl;
	// 	hdr.ip_dup.dscp = hdr.ipv4.dscp;
	// 	hdr.ip_dup.ecn = hdr.ipv4.ecn;
	// 	hdr.ip_dup.totalLen = hdr.ipv4.totalLen;
	// 	hdr.ip_dup.identification = hdr.ipv4.identification;
	// 	hdr.ip_dup.flags = hdr.ipv4.flags;
	// 	hdr.ip_dup.fragOffset = hdr.ipv4.fragOffset;
	// 	hdr.ip_dup.ttl = hdr.ipv4.ttl;
	// 	hdr.ip_dup.protocol = hdr.ipv4.protocol;
	// 	hdr.ip_dup.hdrChecksum = hdr.ipv4.hdrChecksum;
	// 	hdr.ip_dup.srcAddr = hdr.ipv4.srcAddr;
	// 	hdr.ip_dup.dstAddr = hdr.ipv4.dstAddr;
	// }

	apply{
		//dbg_dup_ipv4();
		// if ((hdr.ipv4.isValid()) && (hdr.ipv4.ttl > 1) && (standard_metadata.instance_type == 0)){
		// 	send_to_control_plane();
		// }

		if ((hdr.ipv4.isValid()) && (hdr.ipv4.ttl > 1) && (standard_metadata.instance_type == 0)){
		 	if (meta.err_type == PROC_ID_CONFLICT){
				 send_to_control_plane();
				 drop();
			}
			else if (meta.err_type == HASH_COLLISION){
				send_to_control_plane();
			}
		}
		
		if (standard_metadata.instance_type == 2){    // E2E
			hdr.CPU.setValid();
			hdr.CPU.old_pid = meta.hash_pid;
			hdr.CPU.buc_id = meta.hash_buc_key;
			hdr.CPU.hash_id = meta.hash_id;
			hdr.CPU.err_type = meta.err_type;
		}
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta)
{
	apply
	{
		update_checksum(
			hdr.ipv4.isValid(),
			{hdr.ipv4.version,
			 hdr.ipv4.ihl,
			 hdr.ipv4.dscp,
			 hdr.ipv4.ecn,
			 hdr.ipv4.totalLen,
			 hdr.ipv4.identification,
			 hdr.ipv4.flags,
			 hdr.ipv4.fragOffset,
			 hdr.ipv4.ttl,
			 hdr.ipv4.protocol,
			 hdr.ipv4.srcAddr,
			 hdr.ipv4.dstAddr},
			hdr.ipv4.hdrChecksum,
			HashAlgorithm.csum16);

		

		update_checksum_with_payload(
			hdr.int_hdr.isValid(),
			{hdr.ipv4.srcAddr,
			hdr.ipv4.dstAddr,
			8w0,
			hdr.ipv4.protocol,
			hdr.udp.length,
			hdr.udp.srcPort,
			hdr.udp.dstPort,
			hdr.udp.length,
			hdr.int_hdr},
			hdr.udp.checksum,
			HashAlgorithm.csum16);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
	MyParser(),
	MyVerifyChecksum(),
	MyIngress(),
	MyEgress(),
	MyComputeChecksum(),
	MyDeparser()) main;
