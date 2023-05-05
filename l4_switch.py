from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import in_proto
from ryu.lib.packet import arp




class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table= {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
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
        self.add_flow(datapath, 0, match, actions)
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
        ethtype = eth.ethertype
        if ethtype == 2054: self.arpHandler(msg) 

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        ip = pkt.get_protocol(ipv4.ipv4)
        arp_pkt= pkt.get_protocol(arp.arp)
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        #if eth.ethertype == ether_types.ETH_TYPE_ARP:
            #match_arp=parser.OFPMatch(eth_type= 0x800, arp_src= ip_src, arp_dst=ip_dst)
      
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip =arp_pkt.dst_ip
            #match_arp=parser.OFPMatch(eth_type= 0x800, arp_src=src_ip, arp_dst=dst_ip)
            self.mac_to_port[dpid][src_ip] = in_port

            if dst_ip in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst_ip]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]


        if ip is not None:
            src_ip= ip.src
            dst_ip = ip.dst        
# learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src_ip] = in_port

            if dst_ip in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst_ip]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
                if eth.ethertype == ether_types.ETH_TYPE_IP:
                    ip = pkt.get_protocol(ipv4.ipv4)
                    src_ip= ip.src
                    dst_ip = ip.dst
                    protocol = ip.protc
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src = src_ip, ipv4_dst =dst_ip)
         
                    if protocol == in_proto.IPPROTO_ICMP:
                   
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src = src_ip, ipv4_dst =dst_ip, ip_proto =protocol)
                    elif protocol == in_protocIPPROTO_TCP:
                        _tcp = pkt.get_protocol (tcp.tcp)
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src = src_ip, ipv4_dst =dst_ip, tcp_src= _tcp.src_port, ip_proto =protocol, tcp_dst= _tcp.dst_port)
                    elif protocol == in_proto.IPPROTO_UDP:
                        _udp = pkt.get_protocol (udp.udp)
                        match= parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src = src_ip, ipv4_dst =dst_ip, ip_proto =protocol,  udp_src= _udp.src_port, udp_dst= _udp.dst_port)
            
         

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
        
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        match =parser.OFPMatch(in_port = in_port, vlan_id = vlan_id|ofproto_v1_3.OFPVID_PRESENT)
        self.add_flow(datapath, 1, match, actions)
        self.send_packet_out(datapath,msg.buffer_id, msg.data, actions)
