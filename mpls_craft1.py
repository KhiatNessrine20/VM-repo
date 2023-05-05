from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet, ethernet, mpls, ipv4



class mpls(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(mpls, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.label = 16
        self.dst_to_label = {} 

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
    def switch_features_handler(self, ev): 
      datapath = ev.msg.datapath
      ofproto = datapath.ofproto
      parser = datapath.ofproto_parser
      match = parser.OFPMatch()
      actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
      self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id= None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser 
        inst =[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath,buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
             mod = parser.OFPFlowMod(datapath=datapath,priority=priority,match=match,instructions=inst) 
        datapath.send_msg(mod)

    # This method will be called whenever a packet arrives at the switch.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Parse the packet data.
        if ev.msg.msg_len < ev.msg.total_len: 
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len) 
         
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]    
        dpid = datapath.id
        
        dst  = eth.dst
        src = eth.src     
        ethtype = eth.ethertype
        self.mac_to_port.setdefault(dpid, {}) 
        self.dst_to_label.setdefault(dpid, {})
        print (self.mac_to_port)

        # If ARP 
        if ethtype == 2054: self.arpHandler(msg) 
         # If IPV4 
        elif ethtype == 2048: self.ipv4Handler(msg) 
        #If MPLS unicast
        elif ethtype == 34887: self.mplsHandler(msg)
        
        

    def arpHandler(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        self.logger.info("Launching ARP handler for datatpath %s", dpid)
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        ethtype = eth.ethertype
# learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
             # install a flow to avoid packet_in next time
        actions = [parser.OFPActionOutput(out_port)]
            
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, eth_type=ethtype)
            self.logger.info("Flow match: in_port=%s, src=%s, dst=%s, type=ARP", in_port, src, dst)
            self.logger.info("Flow actions: out_port=%s", out_port)
            # verify if we have a valid buffer_id, if yes avoid to send
            # both # flow_mod & packet_out         
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            out = parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def ipv4Handler(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port =  msg.match['in_port']
        dpid = datapath.id
        self.logger.info("Launching IPV4 handler for datatpath %s", dpid) 
        pkt = packet.Packet(msg.data) 
        eth = pkt.get_protocols(ethernet.ethernet)[0] 
        dst = eth.dst
        ethtype = eth.ethertype
          
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype)
        self.label = self.label + 1
        self.dst_to_label[dpid][dst] = self.label 
# Set the out_port using the relation learnt with the ARP packet
        out_port = self.mac_to_port[dpid][dst]
# Set the action to be performed by the datapath        
        actions = [parser.OFPActionPushMpls(ethertype=34887,type_=None, len_=None),parser.OFPActionSetField(mpls_label=self.label),parser.OFPActionOutput(out_port)]
        self.logger.info("Flow match: in_port=%s, dst=%s, type=IP", in_port, dst)
        self.logger.info("Flow actions: pushMPLS=%s, out_port=%s", self.label, out_port)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            out = parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def mplsHandler(self,msg):
            # Variables needed:
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        self.logger.info("Launching MPLS Handler for datatpath %s", dpid)
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        mpls_proto = pkt.get_protocol(mpls.mpls)
        dst  = eth.dst
        #src = eth.src      
        ethtype = eth.ethertype
# The switch can be a LSR or a LER, but the match is the same 
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype, mpls_label=mpls_proto.label)
        self.logger.info("Flow match: in_port=%s, dst=%s, type=IP, label=%s", in_port, dst, mpls_proto.label)
        # Set the out_port using the relation learnt with the ARP packet 
        out_port = self.mac_to_port[dpid][dst]
        # we must check the switch ID in order to decide the propper action
        if dpid == 2 or dpid == 4:
            # The switch is a LSR # New label           
            self.label = self.label + 1
            # Switch labels 
            actions = [parser.OFPActionPopMpls(), parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=self.label), parser.OFPActionOutput(out_port)]
            self.logger.info("Flow actions: switchMPLS=%s, out_port=%s", self.label, out_port)
        else:
                 # The switch is a LER # Pop that label! 
            actions = [parser.OFPActionPopMpls(), parser.OFPActionOutput(out_port)]
            self.logger.info("Flow actions: popMPLS, out_port=%s", out_port)
            # Install a flow # verify if we have a valid buffer_id, if
            # yes avoid to send both # flow_mod & packet_out 
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            return
        else:
            self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,actions=actions, data=data)
            datapath.send_msg(out)









