from ryu.base import app_manager 
from ryu.controller import ofp_event 
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER 
from ryu.controller.handler import set_ev_cls 
from ryu.ofproto import ofproto_v1_3 
from ryu.lib.packet import packet 
from ryu.lib.packet import ethernet 
class Switch(app_manager.RyuApp): 
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] 
    def __init__(self, *args, **kwargs): 
        super(Switch, self).__init__(*args, **kwargs)
        # maybe you need a global data structure to save the mapping 
        
        '''
        portIn = mac_to_port[Sw][src]
        portOut = mac_to_port[Sw][dst]
        '''
        
        self.mac_to_port = {}


    def add_flow(self, datapath, priority, match, actions,idle_timeout=0,hard_timeout=0):
        dp = datapath 
        ofp = dp.ofproto 
        parser = dp.ofproto_parser 
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] 
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, 
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
        						match=match,instructions=inst) 
        dp.send_msg(mod) 
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
    def switch_features_handler(self, ev): 
        msg = ev.msg 
        dp = msg.datapath 
        ofp = dp.ofproto 
        parser = dp.ofproto_parser
        match = parser.OFPMatch() 
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)] 
        self.add_flow(dp, 0, match, actions)
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) 
    def packet_in_handler(self, ev): 
        # method-def (Packet-in): self -- An event
        msg = ev.msg # message object
        dp = msg.datapath # data object
        ofp = dp.ofproto  # constants about OpenFlow
        parser = dp.ofproto_parser # parser to construct and analysis OpenFlow Messages
        
        # the identity of switch 
        dpid = dp.id # Sw.id
        self.mac_to_port.setdefault(dpid,{}) # add {empty} into Sw.
        
        # the port that receive the packet 
        in_port = msg.match['in_port'] # the portNumber of this packet
        pkt = packet.Packet(msg.data) 
        eth_pkt = pkt.get_protocol(ethernet.ethernet) 
        
        # get the mac addr.
        dst = eth_pkt.dst # destination node
        src = eth_pkt.src # source node
        
        # we can use the logger to print some useful information 
        self.logger.info('packet: %s %s %s %s', dpid, src, dst, in_port)
        
        # you need to code here to avoid the direct flooding 
        
        '''
        src--in_port--|Sw = dpid|--aim_port--dst
        '''
        
        self.mac_to_port[dpid][src] = in_port
        currentSw = self.mac_to_port[dpid]
        flag = 0 # judge if it's a new mapping
        
        if dst in currentSw:
            aim_port = self.mac_to_port[dpid][dst]
        else:
            aim_port = ofp.OFPP_FLOOD
            flag = 1
        
        actions = [parser.OFPActionOutput(aim_port)]
        
        if (flag):
            # a new mapping, add the flow table to switch
            portMacPair = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(dp, 10, portMacPair, actions) # avoid flow table shadowing (prio = 10)

