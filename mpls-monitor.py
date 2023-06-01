from ryu.base import app_manager
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import networkx as nx
from ryu.lib.packet import mpls, ipv4, ipv6
from itertools import permutations
from collections import defaultdict
import time
from operator import attrgetter


class MplsController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MplsController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        self.paths=[]
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.port_speed = {}    # record the port speed 
        self.flow_speed = {}    # record the flow speed
        self.sleep = 2         # the interval of getting statistic
        self.state_len = 3      # the length of speed list of per port and flow.
        self.port_stats = {}
        self.port_bandwidth = {}
        self.mac_to_port = {}
        self.net = nx.DiGraph()
        self.links = {}
        self.switches = {}
        self.switch_ports = {}
        self.port_stats = {}
        self.flow_stats = {}
        self.stats = {}
        self.port_features = {}
        self.free_bandwidth = {}
        self.topology_api_app= self    
        self.paths= []
        self.statRecord = []
        self.prev_byte_count = {}
        self.prev_time = {}
        self.label = 16
        self.TTL = 64

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    
    def _request_stats(self, datapath):
        """
            Sending request msg to datapath
        """
        
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

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
        data=pkt_mpls.data
        actions = [parser.OFPActionOutput(out_port)]
       
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=pkt_mpls.data)
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
       
        data=pkt_mpls.data
        
        
        actions = [parser.OFPActionOutput(2)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=pkt_mpls.data)
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
      
        data=pkt_ipv4.data
      
        actions = [parser.OFPActionOutput(3)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=pkt_ipv4.data)
        
        datapath.send_msg(out)
        self.add_flow(datapath, 1, match, actions)
    def _get_free_bw(self, capacity, speed):
        # BW:Mbit/s
        print("Received Speed:", speed)
        return max(capacity / 1000 - speed * 8, 0)
    
    def _save_freebandwidth(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        #port_feature = (config, state, p.curr_speed)
        #self.port_features[dpid][p.port_no] = port_feature

        #port_no = msg.desc.port_no
        
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            capacity = port_state[2]
            curr_bw = self._get_free_bw(capacity, speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = {'speed': speed, 'free_port_bw': curr_bw}
           
           # print("Current bw is:", curr_bw)
            #print("Capqcity is:", capacity)
            #print("Speed used:", speed)
            
        else:
            self.logger.info("Fail in getting port state")
        

    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)
    
    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
    # Your existing code to get links and switches data
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
            #print('---Links are:------')
            # print(self.links)
            #print('--Switch ports:--------')
            # print(self.switch_ports)
            #print ("SWITCHES Are:")
            # print (self.switches )
    # Determine all possible paths between switches
        switch_combinations = permutations(self.switches, 2)
        paths = []
        path_id = 1  # Start with path ID 1
        for src_dpid, dst_dpid in switch_combinations:
            if src_dpid == 1 and dst_dpid ==4:
        #try:

            # Use NetworkX library to find the shortest path
                path = list(nx.all_shortest_paths(self.net, src_dpid, dst_dpid))
                paths.append((path_id, path))  # Store path along with its ID
                path_id += 1  # Increment path ID
       # except nx.NetworkXNoPath:
            # No path exists between the switches
            #pass

    # Store each path separately along with its ID
        self.paths = paths
       
         #print ("Available paths are:")
        for path in self.paths:
            # Separate and access individual paths
    
            path_2 = path[1]
            path_3 = path_2[0]
            path_4 = path_2[1]
             # Print the individual paths
            print("--------------Toplogy Paths:----------------------------------")
            print("All Paths are :", path_2)
            print("Path 1 is:", path_3)
            print("Path 2 is:", path_4)
            print("--------------------------------------------------------------")

    def get_path(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.net=nx.DiGraph()
        
        if src not in self.net: #Learn it
            self.net.add_node(src) # Add a node to the graph
            self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
            self.net.add_edge(dpid,src,port=msg.match['in_port'])  # Add link from switch to node and make sure you are identifying the output port.
        if dst in self.net:
            path=nx.shortest_path(self.net,src,dst) # get shortest path  
            next=path[path.index(dpid)+1] #get next hop
            out_port=self.net[dpid][next]['port'] #get output port
            
            
            print ('---the path is :----')
            print (path)
            return out_port
        return None
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        msg = ev.msg
        datapath = msg.datapath
        dpid= datapath.id
        flow_data = {}
        self.logger.info('datapath       '
                        'in-port    eth-dst       '
                        'out-port   packets    bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            self.logger.info('%016x %8x  %17s %8x %8d %8d', ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'], stat.instructions[0].actions[0].port, stat.packet_count, stat.byte_count)
           
            in_port = stat.match['in_port']
            eth_dst = stat.match['eth_dst']
            out_port = stat.instructions[0].actions[0].port
        # Get the byte count and current time
            byte_count = stat.byte_count
            current_time = time.time()
        
        # Create a unique key for each flow
            flow_key = (dpid, in_port, eth_dst, out_port)
        
        # Check if the flow key exists in the dictionary
            if flow_key in flow_data:
                prev_byte_count, prev_time = flow_data[flow_key]
            
            # Calculate the time difference
                time_diff = current_time - prev_time
            
            # Calculate the byte difference
                byte_diff = byte_count - prev_byte_count
            
            # Calculate the flow speed (bytes per second)
                flow_speed = byte_diff / time_diff
                speed = byte_diff* 8 /time_diff
                speed_Kbs = speed /1000
                capacity = 10000000
                av_bw= self._get_free_bw(capacity, speed)
            
            # Print or process the flow speed as desired
                print(f"Flow Speed for {flow_key}: {flow_speed} bytes/s")
                print("Flow Speed for {flow_key}:", speed_Kbs," Kbytes/s")
                print("La Bandwidth is:", av_bw)
        # Update the flow data in the dictionary
            flow_data[flow_key] = (byte_count, current_time)
           # key = (stat.priority, stat.match.get('in_port'), stat.match.get('eth_dst'))
            #value = (stat.packet_count, stat.byte_count,
					# stat.duration_sec, stat.duration_nsec)
            #self._save_stats(self.flow_stats[dpid], key, value, 5)

            #pre = 0
	    #period = 10
	    #tmp = self.flow_stats[dpid][key]
	    #if len(tmp) > 1:
		#pre = tmp[-2][1]
		#period = self._get_period(tmp[-1][2], tmp[-1][3], tmp[-2][2], tmp[-2][3])
	    #speed = self._get_speed(self.flow_stats[dpid][key][-1][1], pre, period)
		            
            #in_port = stat.match['in_port']
            #eth_dst = stat.match['eth_dst']
            #out_port = stat.instructions[0].actions[0].port
            #packet_count = stat.packet_count
            #byte_count = stat.byte_count
            
            #if (dpid, in_port, eth_dst) in self.prev_byte_count:
             #   prev_byte = self.prev_byte_count[(dpid, in_port, eth_dst)]
               # prev_t = self.prev_time[(dpid, in_port, eth_dst)]
            
            

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
            Save port description info.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Farward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        state_dict = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}

        ports = []
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.curr, p.advertised,
                          p.supported, p.peer, p.curr_speed,
                          p.max_speed))

            if p.config in config_dict:
                config = config_dict[p.config]
            else:
                config = "up"

            if p.state in state_dict:
                state = state_dict[p.state]
            else:
                state = "up"

            port_feature = (config, state, p.curr_speed)
           
            if dpid not in self.port_features:
               self.port_features[dpid]= {}
            self.port_features[dpid][p.port_no] = port_feature 
 
   
    

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
        out_port = self.get_path(ev)
        if  out_port is not None:
            
            out_port = out_port
            
        else: 
            out_port = ofproto.OFPP_FLOOD
        if ethtype == 2048 and dpid == "0000000000000001":
            self.push_mpls(ev, out_port)
        
        if ethtype ==ether_types.ETH_TYPE_MPLS and dpid == "0000000000000003":
            self.swap_mpls(ev, out_port)
        if ethtype ==ether_types.ETH_TYPE_MPLS and dpid == "0000000000000002":
            self.swap_mpls(ev, out_port)
        if  ethtype ==ether_types.ETH_TYPE_MPLS and dpid == "0000000000000004":
            self.pop_mpls(ev, out_port)
        
        
        data = msg.data
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
       
