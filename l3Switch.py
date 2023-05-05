from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Create flow mod message and send it to the switch
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Parse the packet
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        dpid = datapath.id
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        #dst_ip= ipv4_pkt.dst
        #src_ip= ipv4_pkt.src
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        
        
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] =in_port
   
        # Handle only IPv4 packets
        if eth_pkt.ethertype == ipv4_pkt:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            dst_ip = ip_pkt.dst
            src_ip = ip_pkt.src
            match = parser.OFPMatch(eth_type=eth_pkt.ethertype, ipv4_src = src_ip, ipv4_dst=dst_ip)

            # Lookup the output port for the destination IP address
            if dst_ip in self.mac_to_port:
                out_port = self.mac_to_port[dst_ip]
            else:
                out_port = ofproto.OFPP_FLOOD

            # Install a flow entry for the destination IP address
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(eth_type=eth_pkt.ethertype, ipv4_dst=dst_ip)
            self.add_flow(datapath, 1, match, actions)

        # Send the packet out the appropriate port
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions)
            datapath.send_msg(out)
