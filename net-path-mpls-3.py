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
from ryu.lib.packet import ethernet, mpls, ipv4

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.net = nx.Graph()
        self.links = {}
        self.switches = {}
        self.switch_ports = {}
        self.topology_api_app= self
        self.dst_to_label ={}  # stores the mapping between the dest add and the label for each datapath
        self.label = 16  # initialisation des labels  

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
        ethtype = eth.ethertype 
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid,{'src'})
       
      
        if ethtype == 2054:
            self.ip_handler(ev) 
        elif ethtype ==34887:
            self.mpls_handler(ev)
        
        

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)

        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        # Store links and switches data in the class variables
        self.links = links
        self.switches = switches

        # Determine input and output ports for each switch
        for src_dpid, dst_dpid, link_info in links:
            if src_dpid not in self.switch_ports:
                self.switch_ports[src_dpid] = {'in_port': [], 'out_port': []}

            if dst_dpid not in self.switch_ports:
                self.switch_ports[dst_dpid] = {'in_port': [], 'out_port': []}

            # Add the input and output ports for each switch
            self.switch_ports[src_dpid]['out_port'].append(link_info['port'])
            self.switch_ports[dst_dpid]['in_port'].append(link_info['port'])
            print('---Links are:------')
            print(self.links)
            print('--Switch ports:--------')
            print(self.switch_ports)
        
        return links, switches
    def ip_handler(self, ev):
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
       
        self.net=nx.Graph()
        if src not in self.net: #Learn it
            self.net.add_node(src) # Add a node to the graph
            self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
            self.net.add_edge(dpid,src,port=msg.match['in_port'])  # Add link from switch to node and make sure you are identifying the output port.
        if dst in self.net:
            path=nx.shortest_path(self.net,eth.src,eth.dst) # get shortest path  
            next=path[path.index(dpid)+1] #get next hop
            out_port=self.net[dpid][next]['port']
        
         #get output port
                
        else:
            out_port = ofproto.OFPP_FLOOD

        # install a flow to avoid packet_in next time
        
        self.logger.info("Flow match: in_port=%s, dst=%s, type=%s, label=%s", in_port, eth.dst,ethtype, self.label)
            # Set the out_port using the relation learnt with the ARP packet 
        if dpid == 1:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype)
              # We relate a label to the destination: We select an
              # unused label 
            self.label = self.label + 1
            
            
           
                
            actions =[parser.OFPActionPushMpls(ethertype=34887,type_=None, len_=None),parser.OFPActionSetField(mpls_label=self.label),parser.OFPActionOutput(out_port)]
            


            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

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
          

    def mpls_handler(self, ev):
       
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
       
        self.net=nx.Graph()
        if src not in self.net: #Learn it
            self.net.add_node(src) # Add a node to the graph
            self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
            self.net.add_edge(dpid,src,port=msg.match['in_port'])  # Add link from switch to node and make sure you are identifying the output port.
        if dst in self.net:
            path=nx.shortest_path(self.net,eth.src,eth.dst) # get shortest path  
            next=path[path.index(dpid)+1] #get next hop
            out_port=self.net[dpid][next]['port']
        
         #get output port
                
        else:
            out_port = ofproto.OFPP_FLOOD


        if dpid== 2 or dpid== 3:
            
            self.label = self.label + 1
            # Switch labels 
             
            
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype, mpls_label=mpls_proto.label)
                
            self.logger.info("Flow actions: switchMPLS=%s, out_port=%s", self.label, out_port)
            actions = [parser.OFPActionPopMpls(), parser.OFPActionPushMpls(), parser.OFPActionSetField(mpls_label=self.label), parser.OFPActionOutput(out_port)]
                

        elif dpid == 4:
         
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=ethtype, mpls_label=mpls_proto.label)
          
            self.logger.info("Flow actions: popMPLS, out_port=%s", out_port)
            actions = [parser.OFPActionPopMpls(), parser.OFPActionOutput(out_port)]
                

       
            
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

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



        
    
    
    
