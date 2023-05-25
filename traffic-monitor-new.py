from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
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
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
   
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath '
                         'in-port eth-dst '
                         'out-port packets bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d', ev.msg.datapath.id, stat.match['in_port'], stat.match['eth_dst'], stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
            
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.logger.info('datapath port '
                         'rx-pkts rx-bytes rx-error '
                         'tx-pkts tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                        '-------- -------- -------- '
                         '-------- -------- --------')

        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                         ev.msg.datapath.id, stat.port_no,
                         stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                         stat.tx_packets, stat.tx_bytes, stat.tx_errors)

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
        """
        Save flow stats reply info into self.flow_stats.
        Calculate flow speed and save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        if 'flow' not in self.stats:
            self.stats['flow'] = {}

        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})

        for stat in sorted([flow for flow in body if flow.priority == 1],
                       key=lambda flow: (flow.match.get('in_port'),
                                         flow.match.get('ipv4_dst'))):
            key = (stat.match['in_port'],  stat.match.get('ipv4_dst'),
               stat.instructions[0].actions[0].port)
            value = (stat.packet_count, stat.byte_count,
                 stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

            # Get flow's speed.
            pre = 0
            period = 10
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                      tmp[-2][2], tmp[-2][3])

                speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                pre, period)

                self._save_stats(self.flow_speed[dpid], key, speed, 5)
                print("Flow Speed:", speed)


    #///// Updates
    # ----------- Calling and printing the values------------------
    for dpid, port_data in self.free_bandwidth.items():
    print(f"DPID: {dpid}")
    for port_no, port_info in port_data.items():
        speed = port_info['speed']
        free_bw = port_info['free_bw']
        print(f"Port: {port_no}, Speed: {speed}, Free Bandwidth: {free_bw}")
    
    #-------free bw, dpid and port
    def _save_freebandwidth(self, dpid, port_no, speed):
    
    port_state = self.port_features.get(dpid).get(port_no)
    if port_state:
        capacity = setting.MAX_CAPACITY   # The true bandwidth of the link, instead of 'curr_speed'.
        free_bw = self._get_free_bw(capacity, speed)
        self.free_bandwidth[dpid].setdefault(port_no, {})
        self.free_bandwidth[dpid][port_no] = {'speed': speed, 'free_bw': free_bw}
      else:
        self.logger.info("Port is Down")

   #-----------Calculatng Link's bw using the speeds

   def calculate_link_bandwidth(self, dpid1, port_no1, dpid2, port_no2):
    speed1 = self.port_features.get(dpid1).get(port_no1).get('curr_speed')
    speed2 = self.port_features.get(dpid2).get(port_no2).get('curr_speed')
    capacity = setting.MAX_CAPACITY

    total_speed = speed1 + speed2
    link_bandwidth = min(total_speed, capacity)  # Link bandwidth is limited by the minimum of total_speed and capacity

    return link_bandwidth


# ------------Saving the free bandwidth with the correspanding port and dpid qnd speed

def _save_freebandwidth(self, dpid, port_no, speed):
    """
    Calculate free bandwidth of port and save it.
    port_feature = (config, state, p.curr_speed)
    self.port_features[dpid][p.port_no] = port_feature
    self.free_bandwidth = {dpid: {port_no: {'speed': speed, 'free_bw': free_bw}},}
    """
    port_state = self.port_features.get(dpid).get(port_no)
    if port_state:
        capacity = setting.MAX_CAPACITY   # The true bandwidth of the link, instead of 'curr_speed'.
        free_bw = self._get_free_bw(capacity, speed)
        self.free_bandwidth[dpid].setdefault(port_no, {})
        self.free_bandwidth[dpid][port_no] = {'speed': speed, 'free_bw': free_bw}
    else:
        self.logger.info("Port is Down")

