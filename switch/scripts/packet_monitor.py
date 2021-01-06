import nnpy
import time
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import *
import sys
import threading
import argparse
import pdb

class Int_hdr(Packet):
    name = "Int_hdr"
    fields_desc = [\
        BitField("pid", 0, 32)
    ]

class Runtime_info(Packet):
    name = "Runtime_info"

    fields_desc = [\
        BitField("old_pid", 0, 32),
        BitField("buc_id", 0, 32),\
        BitField("hash_fingprint", 0, 32),\
        BitField("err_type", 0, 32),\
    ]


class packetReceicer(threading.Thread):

    # initialization code
    def __init__(self, sw_name, topo_path):
        threading.Thread.__init__(self)

        self.topo = Topology(db=topo_path)  #set the topology

        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.cpu_port =  self.topo.get_cpu_port_index(self.sw_name)
        self.controller = SimpleSwitchAPI(self.thrift_port)
        self.flow = {}
        self.flag = True
        self.init()
        

    def init(self):
        self.add_mirror()
        self.counter = 0
        self.log_name = "../switch_log/" + self.sw_name + ".log"

        self.logs_info=open("../switch_log/" + self.sw_name + "_info.log", "w")
        self.logs_info.write("SWITCH[" + self.sw_name + "]\n")
        self.logs_info.close()

        log_file = open(self.log_name, "w")
        log_file.write("Monitering switch[" + self.sw_name + "]\n")
        log_file.close()

        bind_layers(UDP, Int_hdr, __fval=None)
        bind_layers(Int_hdr, Runtime_info, __fval=None)

    def add_mirror(self):
        if self.cpu_port:
            self.controller.mirroring_add(100, self.cpu_port) # correspond to the 100 in p4 code
            #is there any probability to increase the mirro port to add cpu port?

    #######################################
    # runtime code



    def recv_msg_cpu(self, pkt):
        self.counter += 1

        self.gen_per_packet_log(pkt)

    def gen_per_packet_log(self, pkt):
        pkt_ether = pkt["Ether"]
        pkt_ip = pkt["IP"]
        pkt_udp = pkt["UDP"]
        pkt_int = pkt["Int_hdr"]
        pkt_rt_info = pkt["Runtime_info"]
        #pdb.set_trace()

        addr2str = lambda x: ".".join([str(x/(256**i)%256) for i in range(3,-1,-1)])

        log_file = open(self.log_name, "a+")
        
        log_file.write("Packet_ID: {}\n".format(self.counter))
        log_file.write("Src Addr: {}, Src Port: {}, Dst Addr: {}, Dst Port: {}, Proto: {}\n".format(pkt_ip.src, pkt_ip.dst, pkt_udp.sport, pkt_udp.dport, pkt_ip.proto))
        log_file.write("Packet_PID: {}, Conflicted_PID: {}, Bucket_ID: {}, fingerprint: {} ".format(pkt_int.pid, pkt_rt_info.old_pid, pkt_rt_info.buc_id, pkt_rt_info.hash_fingprint))
        if pkt_rt_info.err_type == 0x1:
            log_file.write("Error Type: PID conflict\n")
            log_file.write("{}\n".format(str(pkt_rt_info["Raw"])))
        else:
            log_file.write("Error Type: Hash conflict\n")

        log_file.close()
    

    def run_cpu_port_loop(self):
        cpu_port_intf = str(self.topo.get_cpu_port_intf(self.sw_name).replace("eth0", "eth1"))
        #the cpu has two ports   could use two thread to sniff
        print(cpu_port_intf)
        print(sniff(iface=cpu_port_intf, prn=self.recv_msg_cpu))
    
    def run(self):
        self.run_cpu_port_loop()


if __name__ == "__main__":
    # usage : python test.py [sw_name]
    # hint: the sw_name must open the cpu_port function in p4app.json
    # "cpu_port" : true

    parser = argparse.ArgumentParser()
    
    parser.add_argument("-s", "--switch", help="this switch's name")
    args = parser.parse_args()

    topo_path = "../p4src_simple/topology.db"
    
    controllers = []

    if args.switch == None:
        num_switch = 1

        for i in range(num_switch):
            controllers.append(packetReceicer("s" + str(i + 1), topo_path))

        for i in range(num_switch):
            controllers[i].start()
        
        for i in range(num_switch):
            controllers[i].join()

    else:
        sw_name = args.switch
        controllers.append(packetReceicer(sw_name, topo_path).run_cpu_port_loop())
