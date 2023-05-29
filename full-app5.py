from ryu.base import app_manager
import traffic_monitor_func_5
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

    _CONTEXTS ={"network_monitor": traffic_monitor_func_5.TrafficMonitor}

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
        self.monitor= kwargs["network_monitor"]
        self.out_port=[]
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
        self.mac_to_port.setdefault(dpid, {})
        mpls_proto = pkt.get_protocol(mpls.mpls)
       
        path1, path2 = self.monitor.get_topology_data(ev)
        print("pathitha 1:", path1)
        print("pathitha 2:", path2)
        for sw in range (0, len(path1)-1):
            next=path1[sw +1]
            print("Next", next)
            if next not in self.net:            
                self.net.add_node(next) # Add a node to the graph
                self.net.add_edge(next,dpid)
                self.net.add_edge(dpid,next,port=msg.match['in_port']) 

                out_port1 = self.net[dpid][next]['port']
                print("out:", out_port1)
                self.out_port= out_port1
                print(self.out_port)
                
       
       
        
        out_port = self.get_path(ev)
        
        if  out_port is not None:
           
            out_port = out_port
            
        else: 
            out_port = ofproto.OFPP_FLOOD
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

