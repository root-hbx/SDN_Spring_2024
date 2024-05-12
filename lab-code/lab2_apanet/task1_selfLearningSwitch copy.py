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

'''
an adaptation in Broadcast_Loop.py
'''

class Switch_Dict(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch_Dict, self).__init__(*args, **kwargs)
        self.sw = {}
        # topo: src--in_port--|Sw = dpid|--aim_port--dst
        # mapping-1: portIn = mac_to_port[Sw][src]
        # mapping-2: portOut = mac_to_port[Sw][dst]
        
        self.mac_to_port = {}

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    # what we actually done:
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # method-def (Packet-in): self -- An event
        
        msg = ev.msg # message object
        dp = msg.datapath # data object
        ofp = dp.ofproto  # constants about OpenFlow
        parser = dp.ofproto_parser # parser to construct and analysis OpenFlow Messages

        # the identity of switch
        dpid = dp.id # Sw.id
        self.mac_to_port.setdefault(dpid, {}) # add {empty} into Sw.
        
        # the port that receive the packet
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_IPV6:
            return
        
        # get the mac
        dst = eth_pkt.dst
        src = eth_pkt.src
        
        # get protocols
        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        if dst == ETHERNET_MULTICAST and ARP in header_list:
            # need to code here to avoid broadcast loop to finish mission 2
            # this part can be passed here
            pass
        
        # self-learning
        # src---in_port---|Sw = dpid|---aim_port---dst
        
        self.mac_to_port[dpid][src] = in_port # mapping-1
        currentSw = self.mac_to_port[dpid]
        flag = 0 # judge if it's a new mapping
        
        # the logic process of OpenFlow Controller
        
        if dst in currentSw:
            aim_port = self.mac_to_port[dpid][dst] # mapping-2
        else:
            aim_port = ofp.OFPP_FLOOD # pre-flooding this packet to all nodes
            flag = 1
        
        # sending to which port (specific one / flooding) depends on "aim_port" above
        actions = [parser.OFPActionOutput(aim_port)]
        
        # a new mapping, add the flow table to switch
        if (flag):
            # create a matching condition, only the pkt (portIn: in_port, dstMac: dst) can satisfy
            portMacPair = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # add this matching into flow table
            self.add_flow(dp, 10, portMacPair, actions) # avoid flow table shadowing (prio = 10)

        '''
        After receiving Pack-In, 
        controller will send Packet-Out to Switch and give orders to the specific packet
        '''
        
        data = None
        # for flow tables, in-time send is necessary
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            # if there's no packetBuffer in Switch, it implies:
            #   this packet is sending to Controller directly!
            #   and we need to copy the "data in packet" into dataMessage
            #   for it will be loaded into "outPut" towards Sw.
            data = msg.data
        
        outPut = parser.OFPPacketOut(
            datapath=dp, # towards the Sw. who is sending Packet-In message
            buffer_id=msg.buffer_id, # the Buffer ID of the packetNum
            in_port=in_port, # the receiving portNum
            actions=actions,
            data=data,
        )
        
        dp.send_msg(outPut)
        