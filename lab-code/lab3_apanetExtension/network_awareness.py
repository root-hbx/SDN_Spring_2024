from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp
from ryu.lib.packet import ether_types
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_host, get_link, get_switch
from ryu.topology.switches import LLDPPacket

import networkx as nx
import copy
import time

# this script is to get network topology by controller
# with the help of Ryu
# all solutions in exp1&2 are listed in this code

GET_TOPOLOGY_INTERVAL = 2
SEND_ECHO_REQUEST_INTERVAL = 0.05
GET_DELAY_INTERVAL = 2

class NetworkAwareness(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkAwareness, self).__init__(*args, **kwargs)
        # basic config info of a topo
        self.switch_info = {}  # dpid: datapath
        self.link_info = {}  # (s1, s2): s1.port
        self.port_link={} # s1,port:s1,s2
        self.port_info = {}  # dpid: (ports linked hosts)
        self.topo_map = nx.Graph()
        self.topo_thread = hub.spawn(self._get_topology)
        self.lldp_delay = {}
        self.delay = {}
        self.controller_switch_delay = {}

        # define weight of path
        self.weight = 'hop' # use "hopNumber between 2 nodes" as weight in ShortPath Choosing
        self.switches = None

    def add_flow(self, datapath, priority, match, actions):
        # add an object to flow_table
        dp = datapath # Sw.
        ofp = dp.ofproto # objects and consts about OpenFlow itself
        parser = dp.ofproto_parser # parser of OpenFlow

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] # Sw: actions after receiving info
        # message downing
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=inst)
        '''
        mod = message downing to Sw.
        dp = Sw.
        prio = the processing Prio.
        match = matching condition
        inst = corresponding actions
        '''
        dp.send_msg(mod)
    
    def delete_flow(self, datapath, match):
        # get this on line
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [] # empty action set for deleting
        
        req = parser.OFPFlowMod (
              dp, 
              0, 0, 0, ofp.OFPFC_DELETE,
              0, 0, 0, ofp.OFP_NO_BUFFER, 
              ofp.OFPP_ANY, 
              ofp.OFPG_ANY, 
              ofp.OFPFF_SEND_FLOW_REM, 
              match,
              inst
        )
        '''
        0, 0, 0: flowTable ID, Prio, Buffer ID
        ofp.OFPFC_DELETE: deleting
        0, 0, 0: overTime (general soft hard)
        ofp.OFP_NO_BUFFER: no buffer allocation
        ofp.OFPP_ANY: delete all ports
        ofp.OFPG_ANY: delete all groups
        ofp.OFPFF_SEND_FLOW_REM: sending "moved" while deleting flowTable
        match: matching part
        inst: empty action set for deleting
        '''
        dp.send_msg(req)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # 在交换机连接时向其添加一个默认的流表项，使所有未匹配到的流量都发送到控制器
        msg = ev.msg # message of packet
        dp = msg.datapath # Sw.
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch() # MatchObject = None, matching all flows
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)] # sending corresponding (all) flows to Controller
        '''
        ofp.OFPP_CONTROLLER: Controller Receiving Port
        ofp.OFPCML_NO_BUFFER: no Buffer for this msg
        '''
        self.add_flow(dp, 0, match, actions) # matching all, so prio = 0

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        # gandle Sw. port changing
        msg = ev.msg
        datapath = ev.datapath
        ofproto = ev.ofproto
        parser = datapath.ofproto_parser
        
        # the kind of change
        if msg.reason in [ofproto.OFPPR_ADD, ofproto.OFPPR_MODIFY]:
            # add / modify: overwrite the mapping of changing port
            datapath.ports[msg.desc.port_no] = msg.desc
            # clear old topology
            self.topo_map.clear()
            
            for dpid in self.port_info.keys(): # linked-path
                for port in self.port_info[dpid]: # corresponding ports of these path
                    match = parser.OFPMatch(in_port = port)
                    self.delete_flow(self.switch_info[dpid], match) # delete flowTable
        elif msg.reason == ofproto.OFPPR_DELETE:
            # delete: remove this port
            datapath.ports.pop(msg.desc.port_no, None)
        else:
            return
        
        # log
        self.send_event_to_observers(ofp_event.EventOFPPortStateChange(datapath,msg.reason, msg.desc.port_no),datapath.state)
        
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        # 当交换机状态改变时（连接或断开），会触发该方法: 处理交换机连接和断开事件，更新内部数据结构
        dp = ev.datapath # Sw.
        dpid = dp.id # Sw.ID

        if ev.state == MAIN_DISPATCHER: # Sw. is in connection (ON)
            self.switch_info[dpid] = dp # add map<ID, Sw.>

        if ev.state == DEAD_DISPATCHER: # Sw. is out of connection (OFF)
            del self.switch_info[dpid] # del ...
        
    @set_ev_cls(ofp_event.EventOFPEchoReply, [MAIN_DISPATCHER,CONFIG_DISPATCHER,HANDSHAKE_DISPATCHER])
    def echo_reply_handler(self, ev):
        now_timestamp = time.time()
        try:
            echo_delay = now_timestamp - eval(ev.msg.data) # currentTime - sendTime
            self.controller_switch_delay[ev.msg.datapath.id] = echo_delay * 1000
        except:
            print ("Overtime! Error!")
            return
    
    def send_echo_request(self, switch):
        datapath = switch.dp
        parser = datapath.ofproto_parser
        echo_req = parser.OFPEchoRequest(datapath, data=bytes("%.12f"%time.time()))
        datapath.send_msg(echo_req)
    
    '''
    echo_reply_handler: 处理和解析从交换机接收到的 Echo Reply 消息，计算延迟并存储
    send_echo_request:  向交换机发送 Echo Request 消息，包含发送时间戳
    
    - 控制器通过 send_echo_request 主动发送 Echo Request 消息。
    - 交换机收到 Echo Request 消息后，回应 Echo Reply 消息。
    - 控制器接收到 Echo Reply 消息时，调用 echo_reply_handler 计算和记录延迟
    '''

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        PacketIn 事件在Sw.接收到数据包并将其发送到controller时触发
        该方法处理接收到的数据包, 并在特定情况下(LLDP)执行特定的操作
        '''
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        dpid = dp.id # datapath ID
        
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        pkt_type = eth_pkt.ethertype
        
        if pkt_type == ether_types.ETH_TYPE_LLDP:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
            if self.switches is None:
                '''
                在控制器启动并且尚未处理任何 PacketIn 事件之前，
                self.switches 很可能是 None, 因为它还没有被初始化           
                '''
                self.switches = lookup_service_brick('switches')
            
            for port in self.switches.ports.keys():
                if src_dpid == port.dpid and src_port_no == port.port_no:
                    self.lldp_delay[(src_dpid,dpid)] = self.switches.ports[port].delay * 1000
                
    def _get_topology(self):
        _hosts, _switches, _links = None, None, None
        while True:
            hosts = get_host(self)
            switches = get_switch(self)
            links = get_link(self)

            # If topo is still, continue
            if [str(x) for x in hosts] == _hosts and [str(x) for x in switches] == _switches and [str(x) for x in links] == _links:
                continue
            
            # update topo_map when topology change
            _hosts, _switches, _links = [str(x) for x in hosts], [str(x) for x in switches], [str(x) for x in links] # get new topo elements

            for switch in switches: # ports & Sw.
                self.port_info.setdefault(switch.dp.id, set()) # origin, a Sw. with nothing
                # record all ports in this Sw.
                for port in switch.ports:
                    self.port_info[switch.dp.id].add(port.port_no) # attach ports in this Sw.
                self.send_echo_request(switch)
                hub.sleep(0.5)
                
            for host in hosts: # Sw. & hosts
                # take one ipv4 address as host id
                if host.ipv4:
                    self.link_info[(host.port.dpid, host.ipv4[0])] = host.port.port_no
                    self.topo_map.add_edge(host.ipv4[0], host.port.dpid, hop=1, delay=0, is_host=True) # hop=1: host connect Sw. directly
                    
            for link in links:
                # delete link (host-port -- link -- host-port) 
                self.port_info[link.src.dpid].discard(link.src.port_no)
                self.port_info[link.dst.dpid].discard(link.dst.port_no)

                # s1 -> s2: s1.port, s2 -> s1: s2.port
                self.port_link[(link.src.dpid,link.src.port_no)]=(link.src.dpid, link.dst.dpid) # src-srcPort -- dst
                self.port_link[(link.dst.dpid,link.dst.port_no)] = (link.dst.dpid, link.src.dpid) # dst-dstPort -- src

                self.link_info[(link.src.dpid, link.dst.dpid)] = link.src.port_no
                self.link_info[(link.dst.dpid, link.src.dpid)] = link.dst.port_no
                # self.topo_map.add_edge(link.src.dpid, link.dst.dpid, hop=1, is_host=False) # linked directly
                
                delay_src_to_dst = 0.0
                delay_dst_to_src = 0.0
                delay_ctl_to_src = 0.0
                delay_ctl_to_dst = 0.0
                
                if (link.src.dpid, link.dst.dpid) in self.lldp_delay:
                    delay_src_to_dst = self.lldp_delay[(link.src.dpid, link.dst.dpid)]
                
                if (link.dst.dpid, link.src.dpid) in self.lldp_delay:
                    delay_dst_to_src = self.lldp_delay[(link.dst.dpid, link.src.dpid)]
                
                if link.src.dpid in self.controller_switch_delay:
                    delay_ctl_to_src = self.controller_switch_delay[link.src.dpid]
                
                if link.dst.dpid in self.controller_switch_delay:
                    delay_ctl_to_dst = self.controller_switch_delay[link.dst.dpid]
                    
                delay = (delay_src_to_dst + delay_dst_to_src + 
                         delay_ctl_to_src + delay_ctl_to_dst) / 2
                
                if (delay < 0): 
                    delay = 0
                
                self.delay[(link.src.dpid, link.dst.dpid)] = delay
                self.topo_map.add_edge(link.src.dpid, link.dst.dpid, hop = 1, delay = delay, is_host = False)

            if self.weight == 'hop':
                self.show_topo_map_1()
            if self.weight == 'delay':
                self.show_topo_map_2()
                
            hub.sleep(GET_TOPOLOGY_INTERVAL)

    def shortest_path(self, src, dst, weight='hop'):
        try:
            # import nx to solve "shortest path" automatically
            paths = list(nx.shortest_simple_paths(self.topo_map, src, dst, weight=weight))
            return paths[0]
        except:
            self.logger.info('host not find/no path')

    def show_topo_map_1(self):
        self.logger.info('topo map:')
        self.logger.info('{:^10s} -> {:^10s} {}'.format('node', 'node','hop'))
        for src, dst in self.topo_map.edges:
            self.logger.info('{:^10s} {:^10s} {}'.format(str(src),
            str(dst),self.topo_map.edges[src,dst]['hop']))
        
        self.logger.info('\n')
        
    def show_topo_map_2(self):
        self.logger.info('topo map:')
        self.logger.info('{:^10s} -> {:^10s} {}'.format('node', 'node','delay'))
        for src, dst in self.topo_map.edges:
            self.logger.info('{:^10s} {:^10s} '.format(str(src),
            str(dst))+'%.1f'%self.topo_map.edges[src,dst]['delay']+'ms')
        self.logger.info('\n')
