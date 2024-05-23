# ryu-manager shortest_forward.py --observe-links
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4
from ryu.lib.packet import ether_types
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.topology.api import get_switch
import sys
from network_awareness1 import NetworkAwareness
import networkx as nx
ETHERNET = ethernet.ethernet.__name__

ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
class ShortestForward(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'network_awareness1': NetworkAwareness}
 
    def __init__(self, *args, **kwargs):
        super(ShortestForward, self).__init__(*args, **kwargs)
        self.network_awareness1 = kwargs['network_awareness1']
        self.weight = 'delay'
        self.mac_to_port = {}
        self.sw = {}
        self.path=None
        self.switches = None
        self.ip_to_mac = {}
        self.mac_to_dpid = {}
        self.dpid_to_dp = {}
        self.ip_to_port = {}
        
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
        datapath=dp, priority=priority,
        idle_timeout=idle_timeout,
        hard_timeout=hard_timeout,
        match=match, instructions=inst)
        dp.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        dpid = dp.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        pkt_type = eth_pkt.ethertype

        # layer 2 self-learning
        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src


        if isinstance(arp_pkt, arp.arp):
            self.handle_arp(msg, in_port, dst_mac,src_mac, pkt, pkt_type)

        if isinstance(ipv4_pkt, ipv4.ipv4):
            self.handle_ipv4(msg, ipv4_pkt.src, ipv4_pkt.dst, pkt_type)
        
    def handle_arp(self, msg, in_port, dst,src, pkt,pkt_type):
        datapath = msg.datapath
        dpid = datapath.id
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        arp_pkg=pkt.get_protocol(arp.arp)
        if arp_pkg.opcode == arp.ARP_REQUEST:
            if arp_pkg.src_ip not in self.ip_to_mac:
                self.ip_to_mac[arp_pkg.src_ip]=src
                self.mac_to_dpid[src]=(dpid,in_port)
                self.ip_to_port[arp_pkg.src_ip]=(dpid,in_port)
            if arp_pkg.dst_ip in self.ip_to_mac:
                self.arpReply(datapath=datapath,port=in_port,src_mac=self.ip_to_mac[arp_pkg.dst_ip],
                dst_mac=src,src_ip=arp_pkg.dst_ip,dst_ip=arp_pkg.src_ip)
            else:
                out_port=ofp.OFPP_FLOOD
                actions=[parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(datapath = datapath, 
                                          buffer_id = msg.buffer_id,
                                          in_port = in_port, 
                                          actions = actions, 
                                          data = msg.data)
                datapath.send_msg(out)
            return
        elif arp_pkg.opcode == arp.ARP_REPLY:
            if arp_pkg.src_ip not in self.ip_to_mac:
                self.ip_to_mac[arp_pkg.src_ip]=src
                self.mac_to_dpid[src]=(dpid,in_port)
                self.ip_to_port[arp_pkg.src_ip]=(dpid,in_port)
            dst_mac=self.ip_to_mac[arp_pkg.dst_ip]
            dst_dpid,dst_port=self.mac_to_dpid[dst_mac]
            switches = get_switch(self)
            
            for switch in switches:
                if dst_dpid == switch.dp.id:
                    self.arpReply(datapath=switch.dp,port=dst_port,
                    src_mac=src,dst_mac=dst_mac,
                    src_ip=arp_pkg.src_ip,dst_ip=arp_pkg.dst_ip)
                return
            
    def send_pkt(self,datapath,port,pkt):
        ofp=datapath.ofproto
        parser=datapath.ofproto_parser
        pkt.serialize()
        data=pkt.data
        actions=[parser.OFPActionOutput(port=port)]
        out=parser.OFPPacketOut(datapath=datapath,buffer_id=ofp.OFP_NO_BUFFER,
        in_port=ofp.OFPP_CONTROLLER,actions=actions,data=data)
        datapath.send_msg(out)
    
    def arpReply(self,datapath,port,src_mac,dst_mac,src_ip,dst_ip):
        pkt=packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806,dst=dst_mac,src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,src_mac=src_mac,
        src_ip=src_ip,dst_mac=dst_mac,dst_ip=dst_ip))
        self.send_pkt(datapath,port,pkt)
        
    def handle_ipv4(self, msg, src_ip, dst_ip, pkt_type):
        parser = msg.datapath.ofproto_parser

        dpid_path = self.network_awareness1.shortest_path(src_ip, dst_ip,weight=self.weight)
        if not dpid_path:
            return
        
        self.path=dpid_path
        # get port path: h1 -> in_port, s1, out_port -> h2
        port_path = []
        for i in range(1, len(dpid_path) - 1):
            in_port = self.network_awareness1.link_info[(dpid_path[i], dpid_path[i - 1])]
            out_port = self.network_awareness1.link_info[(dpid_path[i], dpid_path[i + 1])]
            port_path.append((in_port, dpid_path[i], out_port))
        self.show_path(src_ip, dst_ip, port_path)
        # calc path delay
        
        # send flow mod
        for node in port_path:
            in_port, dpid, out_port = node
            self.send_flow_mod(parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port)
            self.send_flow_mod(parser, dpid, pkt_type, dst_ip, src_ip, out_port, in_port)
        
        # send packet_out
        _, dpid, out_port = port_path[-1]
        dp = self.network_awareness1.switch_info[dpid]
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        dp.send_msg(out)
        
    def send_flow_mod(self, parser, dpid, pkt_type, src_ip, dst_ip, in_port, out_port):
        dp = self.network_awareness1.switch_info[dpid]
        match = parser.OFPMatch(
        in_port=in_port, eth_type=pkt_type, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(dp, 1, match, actions, 10, 30)
        
    def show_path(self, src, dst, port_path):
        self.logger.info('path: {} -> {}'.format(src, dst))
        path_delay = 0
        path = src + ' -> '
        for i in range(len(port_path)):
            path += '{}:s{}:{}'.format(port_path[i][0],port_path[i][1],port_path[i][2]) + '-> '
            
            if i == len(port_path) - 1:
                break
            path_delay += self.network_awareness1.delay[(port_path[i][1],port_path[i+1][1])]
        '''
        for node in port_path:
        path += '{}:s{}:{}'.format(*node) + ' -> '
        '''
        path += dst
        path += " delay=" +'%.1f'%path_delay+ 'ms'
        self.logger.info(path)
        
