from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import networkx as nx
from ryu.lib.packet import mpls, ipv4, ipv6
from itertools import permutations

class MplsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    

    def __init__(self, *args, **kwargs):
        super(MplsController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.net = nx.DiGraph()
        self.links = {}
        self.switches = {}
        self.switch_ports = {}
        self.topology_api_app= self    
        self.label = 16
        self.TTL = 64
        self.paths=[]
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def get_path(self, ev):
      
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.net=nx.DiGraph()
        paths=[]
        path_id=1
        if src not in self.net: #Learn it
            self.net.add_node(src) # Add a node to the graph
            self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
            self.net.add_edge(dpid,src,port=msg.match['in_port'])  # Add link from switch to node and make sure you are identifying the output port.
        if dst in self.net:
            path=nx.shortest_path(self.net,src,dst) # get shortest path 
            paths.append((path_id, path)) 
            next=path[path.index(dpid)+1] #get next hop
            out_port=self.net[dpid][next]['port'] #get output port
            
       
            return out_port
        return None

    def push_mpls(self, ev, out_port):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = format(datapath.id, "d").zfill(16)
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        ethtype = eth.ethertype
        ip_header= ipv4.ipv4(dst='10.0.0.2', src='10.0.0.1')
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype)
        self.label = self.label + 1
        self.logger.info("Flow actions: push MPLS=%s, out_port=%s, dst=%s, dpid=%s ", self.label, out_port, dst, dpid)
        pkt_mpls= packet.Packet()
        pkt_mpls.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_MPLS,
                                  dst=eth.dst,src= eth.src))
        pkt_mpls.add_protocol(mpls.mpls(label= self.label ))
        pkt_mpls.add_protocol(ip_header)
         

        pkt_mpls.serialize()
        data=msg.data
        actions = [ parser.OFPActionPushMpls(ethertype=ether_types.ETH_TYPE_MPLS ),parser.OFPActionSetField(mpls_label=self.label),parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.add_flow(datapath, 1, match, actions)
       
        
    def swap_mpls(self, ev, out_port):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = format(datapath.id, "d").zfill(16)
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        ethtype = eth.ethertype
        ip_header= ipv4.ipv4(dst='10.0.0.2', src='10.0.0.1')
        mpls_proto = pkt.get_protocol(mpls.mpls)
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype, mpls_label=mpls_proto.label )
        
        self.label = self.label + 1
        self.logger.info("Flow actions:  swap MPLS=%s, out_port=%s, dst=%s,  dpid=%s", self.label, out_port, dst, dpid)
        pkt_mpls= packet.Packet()
        pkt_mpls.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_MPLS,
                                  dst=eth.dst,src= eth.src))
        pkt_mpls.add_protocol(mpls.mpls(label= self.label))
        pkt_mpls.add_protocol(ip_header)
      
        pkt_mpls.serialize()
       
        data=msg.data
        
        
        actions = [parser.OFPActionPopMpls(), parser.OFPActionPushMpls(),parser.OFPActionSetField(mpls_label=self.label), parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        
        datapath.send_msg(out)
        self.add_flow(datapath, 1, match, actions)

    def pop_mpls(self, ev, out_port):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = format(datapath.id, "d").zfill(16)
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        ethtype = eth.ethertype
        ip_header= ipv4.ipv4(dst='10.0.0.2', src='10.0.0.1')
        mpls_proto = pkt.get_protocol(mpls.mpls)
        
        if mpls_proto is not None:
            mpls_label=mpls_proto.label
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype, mpls_label=mpls_proto.label )
        else:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype)
        self.logger.info("Flow actions:  Pop MPLS=%s, out_port=%s, dst=%s , dpid=%s", self.label, out_port, dst, dpid)
        ip_header= ipv4.ipv4(dst='10.0.0.2', src='10.0.0.1')
        pkt_ipv4= packet.Packet()
        pkt_ipv4.add_protocol(ethernet.ethernet(ethertype=2054,
                                  dst=eth.dst,src= eth.src))
             
        pkt_ipv4.add_protocol(ip_header)
      
        pkt_ipv4.serialize()
      
        data=msg.data
      
        actions = [parser.OFPActionPopMpls(),parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        
        datapath.send_msg(out)
        self.add_flow(datapath, 1, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
            # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv6= pkt.get_protocol(ipv6.ipv6)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        ethtype = eth.ethertype 
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        mpls_proto = pkt.get_protocol(mpls.mpls)
        
        out_port = self.get_path(ev)
        
       
        if  out_port is not None:
            
            out_port = out_port
            
        else: 
            out_port = ofproto.OFPP_FLOOD
        if dpid == "0000000000000001" and ethtype == 2048 :
            if in_port ==1:
                self.push_mpls(ev, out_port)
            
        elif dpid == "0000000000000001" and ethtype ==ether_types.ETH_TYPE_MPLS:
            if in_port ==2 :
                self.pop_mpls(ev, out_port)
            elif in_port ==3:
                self.pop_mpls(ev, out_port)

        if dpid == "0000000000000003" and ethtype ==ether_types.ETH_TYPE_MPLS :
            self.swap_mpls(ev, out_port)
        if ethtype ==ether_types.ETH_TYPE_MPLS and dpid == "0000000000000002":
            self.swap_mpls(ev, out_port)
        
        #if  ethtype ==ether_types.ETH_TYPE_MPLS and dpid == "0000000000000004":
          #  self.pop_mpls(ev, out_port)

        if ethtype == 2048 and dpid == "0000000000000004":
            if in_port == 3:
                self.push_mpls(ev, out_port)
        if ethtype ==ether_types.ETH_TYPE_MPLS and dpid == "0000000000000004":
            if in_port ==2:
                self.pop_mpls(ev, out_port)
            elif in_port ==1:
                self.pop_mpls(ev, out_port)
        
        data = msg.data
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
           
       
