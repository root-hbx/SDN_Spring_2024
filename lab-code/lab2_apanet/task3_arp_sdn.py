from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types

ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
ARP = arp.arp.__name__
ARP_TIMEOUT = 60


class Switch_Dict(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__ (self, *args, **kwargs):
        super(Switch_Dict, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        # recording the latest TimeNode (a ARP Request Packet coming in)
        self.latest_stamp = {} # dpid, src_ip, dst_ip -> timestamp

    def add_flow (self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst,
        )
        dp.send_msg(mod)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        
        '''
        创建一个动作列表，表示将数据包发送到控制器: 
        - ofp.OFPP_CONTROLLER表示数据包将发送到控制器, ofp.OFPCML_NO_BUFFER表示不需要缓存
        '''
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        '''
        调用add_flow方法向交换机添加流表规则:
        - 这条规则的优先级为0, 表示最低优先级, 匹配所有数据包, 并将它们发送到控制器
        '''
        self.add_flow(dp, 0, match, actions)
        
        # let switch send arp to controller
        '''
        创建一个匹配条件, 匹配目的MAC地址为广播地址 (ETHERNET_MULTICAST) 的数据包。
        '''
        match = parser.OFPMatch(eth_dst=ETHERNET_MULTICAST)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        
        # a little higher priority to make switch must send arp to controller
        '''
        确保交换机会将ARP请求数据包发送到控制器
        '''
        self.add_flow(dp, 1, match, actions)
        
    # what we actually done
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # the identity of switch
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.latest_stamp.setdefault(dpid, {})

        # the port that receive the packet
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        # get the mac
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src
        
        self.logger.info(
            "Pkt-in: SW(%s) Src(%s) Dst(%s) InPort(%s)", dpid, eth_src, eth_dst, in_port
        )
        
        if eth_src not in self.mac_to_port[dpid]:
            # recording srcMAC and mapping(arcMAC, portIn)
            self.mac_to_port[dpid].setdefault(eth_src, {})
            self.mac_to_port[dpid][eth_src] = in_port
        
        # ARP request
        arp_pkt = pkt.get_protocol(arp.arp)
        currentTime = ev.timestamp
        
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            # get the ip
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            
            # arp for the first time
            if arp_src_ip not in self.latest_stamp[dpid]:
                self.latest_stamp[dpid].setdefault(arp_src_ip, {})
                self.latest_stamp[dpid][arp_src_ip][arp_dst_ip] = currentTime
            # another dst ip, update, too
            elif arp_dst_ip not in self.latest_stamp[dpid][arp_src_ip]:
                self.latest_stamp[dpid][arp_src_ip].setdefault(arp_dst_ip, {})
                self.latest_stamp[dpid][arp_src_ip][arp_dst_ip] = currentTime
            # arp for the second time
            elif currentTime - self.latest_stamp[dpid][arp_src_ip][arp_dst_ip] < ARP_TIMEOUT:
                print("duration is not long enough!")
                return
        
        # self-learning
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofp.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
            self.add_flow(dp, 10, match, actions)
        
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data
        )
        dp.send_msg(out)
        
