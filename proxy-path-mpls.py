from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import networkx as nx




class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {"10.0.0.1": "00:00:00:00:00:01",
                    "10.0.0.2": "00:00:00:00:00:02"}
        self.mac_to_port = {}
        self.net = nx.Graph()
        self.links = {}
        self.switches = {}
        self.switch_ports = {}
        self.topology_api_app= self
        self.label = 16

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
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

    def arp_process(self, datapath, eth, a, in_port):
        r = self.arp_table.get(a.dst_ip)
        if r:
            self.logger.info("Matched MAC %s ", r)
            arp_resp = packet.Packet()
            arp_resp.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                                  dst=eth.src, src=r))
            arp_resp.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                  src_mac=r, src_ip=a.dst_ip,
                                  dst_mac=a.src_mac,
                                  dst_ip=a.src_ip))

            arp_resp.serialize()
            actions = []
            actions.append(datapath.ofproto_parser.OFPActionOutput(in_port))
            parser = datapath.ofproto_parser  
            ofproto = datapath.ofproto
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_resp)
            datapath.send_msg(out)
            self.logger.info("Proxied ARP Response packet")

    def mpls_handler(self,ev):
        
        msg = ev.msg
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
        src = eth.src
        ethtype = eth.ethertype
   
        if dpid ==2 or dpid == 3:
            self.label = self.label + 1
            self.logger.info("Flow actions: switchMPLS=%s, out_port=%s", self.label, out_port)
            actions = [parser.OFPActionPopMpls(), parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=self.label), parser.OFPActionOutput(out_port)]
                

        elif dpid == 4:
         
            self.logger.info("Flow actions: popMPLS, out_port=%s", out_port)
            actions = [parser.OFPActionPopMpls(), parser.OFPActionOutput(out_port)]
                
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_resp)
        datapath.send_msg(out)
    def ipv4_handler(self ,ev):
        msg = ev.msg
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
              # We relate a label to the destination: We select an
              # unused label 
        self.label = self.label + 1
        actions =[parser.OFPActionPushMpls(ethertype=34887,type_=None, len_=None),parser.OFPActionSetField(mpls_label=self.label),parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_resp)
        datapath.send_msg(out)









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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        
        self.net=nx.Graph()
        
        if src not in self.net: #Learn it
            self.net.add_node(src) # Add a node to the graph
            self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
            self.net.add_edge(dpid,src,port=msg.match['in_port'])  # Add link from switch to node and make sure you are identifying the output port.
        if dst in self.net:
            path=nx.shortest_path(self.net,src,dst) # get shortest path  
            next=path[path.index(dpid)+1] #get next hop
            out_port=self.net[dpid][next]['port'] #get output port
            
        else:
            out_port = ofproto.OFPP_FLOOD
      
        
            # Set the out_port using the relation learnt with the ARP packet
        # Check whether is it arp packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("Received ARP Packet %s %s %s ", dpid, src, dst)
            a = pkt.get_protocol(arp.arp)
            self.arp_process(datapath, eth, a, in_port)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            self.ipv4_handler(ev)
        elif eth.ethertype == ether_types.ETH_TYPE_MPLS:
            self.mpls_hanlder(ev)
            return
        

         
         
        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
  


    
