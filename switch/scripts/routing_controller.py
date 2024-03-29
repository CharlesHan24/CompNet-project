from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import *
import socket, struct, pickle, os
from scapy.all import Ether, sniff, Packet, BitField
import time
import sys
import argparse

crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]

BUCKET_NUM = 64
BIN_NUM  = 8
TIME_INTERVAL = 1000

class RoutingController(object):

    def __init__(self):
        self.topo = Topology(db="../p4src_simple/topology.db")  #set the topology
        self.controllers = {}                   #the switches
        self.custom_calcs={}
        self.register_num={}
        self.registers={}
        self.init()

        

    def init(self):
        self.connect_to_switches()              
        self.reset_states()
        self.set_table_defaults()
        self.set_custom_calcs()
        self.reset_all_registers()

        self.set_crc_custom_hashes()

    
    

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():# topology line 632
            thrift_port = self.topo.get_thrift_port(p4switch) 
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)

    def reset_states(self):
            [controllers.reset_state() for controllers in self.controllers.values()]

    def set_table_defaults(self):
        for controllers in self.controllers.values():
            controllers.table_set_default("ipv4_lpm", "drop", [])
            controllers.table_set_default("ecmp_group_to_nhop", "drop", [])
    
    def set_custom_calcs(self):
        for p4switch in self.topo.get_p4switches():
            self.custom_calcs[p4switch] = self.controllers[p4switch].get_custom_crc_calcs()
            self.register_num[p4switch] = len(self.custom_calcs[p4switch])     

    def reset_all_registers(self):
        for sw, controller in self.controllers.items():
            for register in controller.get_register_arrays():
                controller.register_reset(register)

 

    def set_crc_custom_hashes(self):
        for sw_name in self.controllers.keys():
            i = 0
            for custom_crc32, width in sorted(self.custom_calcs[sw_name].items()):
                self.controllers[sw_name].set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True, True)
                i+=1

   
    


    def route(self):
        switch_ecmp_groups = {sw_name:{} for sw_name in self.topo.get_p4switches().keys()}
        # self.topo.network_graph.remove_node("sw-cpu")

        for sw_name, controllers in self.controllers.items():
            for sw_dst in self.topo.get_p4switches():

                #if its ourselves we create direct connections
                if sw_name == sw_dst:
                    for host in self.topo.get_hosts_connected_to(sw_name):
                        sw_port = self.topo.node_to_node_port_num(sw_name, host)
                        host_ip = self.topo.get_host_ip(host) + "/32"
                        host_mac = self.topo.get_host_mac(host)

                        #add rule
                        print("table_add at {}:".format(sw_name))
                        self.controllers[sw_name].table_add("ipv4_lpm", "set_nhop", [str(host_ip)], [str(host_mac), str(sw_port)])

                #check if there are directly connected hosts
                else:
                    if self.topo.get_hosts_connected_to(sw_dst):
                        paths = self.topo.get_shortest_paths_between_nodes(sw_name, sw_dst)
                        for host in self.topo.get_hosts_connected_to(sw_dst):

                            if len(paths) == 1:
                                next_hop = paths[0][1]

                                host_ip = self.topo.get_host_ip(host) + "/24"
                                sw_port = self.topo.node_to_node_port_num(sw_name, next_hop)
                                dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_name)

                                #add rule
                                print("table_add at {}:".format(sw_name))
                                self.controllers[sw_name].table_add("ipv4_lpm", "set_nhop", [str(host_ip)],
                                                                    [str(dst_sw_mac), str(sw_port)])

                            elif len(paths) > 1:
                                next_hops = [x[1] for x in paths]
                                dst_macs_ports = [(self.topo.node_to_node_mac(next_hop, sw_name),
                                                   self.topo.node_to_node_port_num(sw_name, next_hop))
                                                  for next_hop in next_hops]
                                host_ip = self.topo.get_host_ip(host) + "/24"

                                #check if the ecmp group already exists. The ecmp group is defined by the number of next
                                #ports used, thus we can use dst_macs_ports as key
                                if switch_ecmp_groups[sw_name].get(tuple(dst_macs_ports), None):
                                    ecmp_group_id = switch_ecmp_groups[sw_name].get(tuple(dst_macs_ports), None)
                                    print("table_add at {}:".format(sw_name))
                                    self.controllers[sw_name].table_add("ipv4_lpm", "ecmp_group", [str(host_ip)],
                                                                        [str(ecmp_group_id), str(len(dst_macs_ports))])

                                #new ecmp group for this switch
                                else:
                                    new_ecmp_group_id = len(switch_ecmp_groups[sw_name]) + 1
                                    switch_ecmp_groups[sw_name][tuple(dst_macs_ports)] = new_ecmp_group_id

                                    #add group
                                    for i, (mac, port) in enumerate(dst_macs_ports):
                                        print("table_add at {}:".format(sw_name))
                                        self.controllers[sw_name].table_add("ecmp_group_to_nhop", "set_nhop",
                                                                            [str(new_ecmp_group_id), str(i)],
                                                                            [str(mac), str(port)])

                                    #add forwarding rule
                                    print("table_add at {}:".format(sw_name))
                                    self.controllers[sw_name].table_add("ipv4_lpm", "ecmp_group", [str(host_ip)],
                                                                        [str(new_ecmp_group_id), str(len(dst_macs_ports))])
		




    def main(self):
        self.route()

        for switch_id, switch_name in enumerate(self.controllers.keys()):
            print("{} {}".format(switch_id, switch_name))



if __name__ == "__main__":
    controllers = RoutingController().main()
