from itertools import permutations
from operator import attrgetter
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
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
from ryu.lib.packet import mpls, ipv4
from collections import defaultdict
import time



class TrafficMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(TrafficMonitor, self).__init__(*args, **kwargs)
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
            print (next)
            return out_port, next
        return None, None

    def _get_free_bw(self, capacity, speed):
        # BW:Mbit/s
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
           
            print("Current bw is:", curr_bw)
            print("Capqcity is:", capacity)
            print("Speed used:", speed)
            
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
      
            return path_3, path_4
   

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
 
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath       '
                        'in-port    eth-dst       '
                        'out-port   packets    bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            self.logger.info('%016x %8x  %17s %8x %8d %8d', ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'], stat.instructions[0].actions[0].port, stat.packet_count, stat.byte_count)


    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        Save port's stats info
        Calculate port's speed and save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        if 'port' not in self.stats:
            self.stats['port'] = {}

        self.stats['port'][dpid] = body
        self.free_bandwidth.setdefault(dpid, {})

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                     stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = 10
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                          tmp[-2][3], tmp[-2][4])

                    speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],pre, period)

                    self._save_stats(self.port_speed, key, speed, 5)
                    self._save_freebandwidth(dpid, port_no, speed)
                    print("Port Speed:", speed)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
		
        body = ev.msg.body
	dpid = ev.msg.datapath.id
	self.statRecord.append(dpid)
	self.stats['flow'][dpid] = body
	self.flow_stats.setdefault(dpid, {})
	self.flow_speed.setdefault(dpid, {})
	for stat in sorted([flow for flow in body if ((flow.priority not in [0, 65535]) and (flow.match.get('ipv4_src')) and (flow.match.get('ipv4_dst')))],key=lambda flow: (flow.priority, flow.match.get('ipv4_src'), flow.match.get('ipv4_dst'))):
	    key = (stat.priority, stat.match.get('ipv4_src'), stat.match.get('ipv4_dst'))
            value = (stat.packet_count, stat.byte_count,
					 stat.duration_sec, stat.duration_nsec)
	    self._save_stats(self.flow_stats[dpid], key, value, 5)

		# Get flow's speed and Save it.
	    pre = 0
	    period = 10 #setting.MONITOR_PERIOD
	    tmp = self.flow_stats[dpid][key]
	    if len(tmp) > 1:
		pre = tmp[-2][1]
		period = self._get_period(tmp[-1][2], tmp[-1][3], tmp[-2][2], tmp[-2][3])
            speed = self._get_speed(self.flow_stats[dpid][key][-1][1], pre, period)
            self._save_stats(self.flow_speed[dpid], key, speed, 5)

            print("Flow Speed:", speed)

    
    def print_dict(self):
       
        for dpid, port_data in self.free_bandwidth.items():
            print(f"DPID: {dpid}")
            for port_no, port_info in port_data.items():
                speed = port_info['speed']
                free_port_bw = port_info['free_port_bw']
                print(f"Port: {port_no}, Speed: {speed}, Free Bandwidth: {free_port_bw}")
    
        #min_path_bw= self.get_path_min_bw(my_graph, path1)
        #print("Path 1's Min-Bandwidth is:", min_path_bw)
        #print("Path 1's Total-Bandwidth is:", total_bw)
        
