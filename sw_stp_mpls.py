from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet, ethernet, mpls
from ryu.lib.packet import ethernet
from ryu.app import simple_switch_13
from ryu.app import simple_switch_stp_13
from ryu.app import simple_switch_13


class mplsclass (simple_switch_stp_13.SimpleSwitch13):
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
        
        def __init__( self, *args, **kwargs):
            super(mplsclass, self).__init__( *args, **kwargs)
            self.mac_to_port= {}   # stores the mapping between the mac add and the port ( li jat meno) for each datapath
            self.dst_to_label ={}  # stores the mapping between the dest add and the label for each datapath
            self.label = 16  # initialisation des labels  


        # La negociation des features between the Controller an dthe switch, asking wsh endk kamel
        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) 
        def switch_features_handler(self, ev):   # ev is a commun way to name an incomong packet wela, it is seenas an event
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto # retourne la version du opfp utilisé par le switch
            parser = datapath.ofproto_parser
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)
        
        def arp_handler(self, ev):
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port'] # indicate from which port this mgs ( packet =) was received
            pkt = packet.Packet(msg.data) # parsing the data 
            eth = pkt.get_protocols(ethernet.ethernet)[0] # get_protocol function extracts the protocols present in that packet, as ethernet is the first protocl header we indexed 0
            dst = eth.dst # extracting the dest mac address from the ethernet packet
            src = eth.src # hna extractng the source
            dpid = datapath.id # extracting the switch's ID ( as switch = datapath)
            ethtype = eth.ethertype
            self.mac_to_port.setdefault(dpid, {}) # creation d'un dictionnaire propore au switch ida mnsh already created with a key as dpid suivi d'un  autre dict
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)  # %s is a string placeholder qui sera remplacer avec dpid;... elhssab tartib
            # in what follows; hn alfo9a we created a dict to map the mac addr to the port w wwsh sra na c que hadk l dict tae mac: port is splitted kinda, cad que rah ywli kayn  fih 2( source mac et le portt & dest mac et son port), thi sway le switch yshfa ela frm win an dto win lpacket ja o lzm yroh ( arp processes)
            #out_port = self.mac_to_port[dpid][dst]
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
            
            data= None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath,buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

        @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
        def _packet_in_handler(self, ev):
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            dst = eth.dst
            src = eth.src
            dpid = datapath.id
            ethtype = eth.ethertype # permet d'extraire le type de protocol du paquet reçu
            self.mac_to_port.setdefault(dpid, {}) # creation d'un dictionnaire propore au switch ida mnsh already created with a key as dpid
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            if ethtype == 2054:
                self.arp_handler(ev)
           # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

         # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
