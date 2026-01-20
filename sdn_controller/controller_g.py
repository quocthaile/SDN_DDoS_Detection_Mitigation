from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp, arp
from ryu.lib import hub
from datetime import datetime
import pandas as pd
import numpy as np
import joblib 
from sklearn.preprocessing import StandardScaler
import time
import os
import sys

class SimpleMonitor13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        self.BLOCK_DURATION = 60
        self.STATUS_INTERVAL = 2
        
        self.blocked_ips = {}           
        self.traffic_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        self.last_status_print = time.time()
        self.flow_history = {} 

        # [MỚI] LỊCH SỬ VI PHẠM (Offender History)
        # Cấu trúc: { '10.0.0.1': {'count': 5, 'methods': {'TCP', 'UDP'}, 'last_seen': '...'} }
        self.offender_history = {} 
        self.HISTORY_FILE = "../attack_log/offender_history.csv"

        # Log Debug
        self.DEBUG_FILE = "debug_ai_prediction.log"
        self._init_debug_log()

        # Load Model
        print("Loading AI Model...")
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(current_dir, '../models/rf_model.pkl')
            scaler_path = os.path.join(current_dir, '../models/scaler.pkl')
            
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                print("-> Model & Scaler loaded successfully!")
            else:
                print(f"ERROR: Model not found at {model_path}")
                self.model = None
        except Exception as e:
            print(f"ERROR loading model: {e}")
            self.model = None

    def _init_debug_log(self):
        with open(self.DEBUG_FILE, "w") as f:
            header = "Timestamp,SrcIP,DstIP,Proto,Delta_Rate(PPS),Feature_Vector_14,PREDICTION,ACTION\n"
            f.write(header)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
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
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, 
                                    eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                                    ip_proto=ip_pkt.proto)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            else:
                self.add_flow(datapath, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            time.sleep(self.STATUS_INTERVAL)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.traffic_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        current_time = time.time()
        
        if current_time - self.last_status_print > 5:
            self._print_network_status()
            self.last_status_print = current_time

        for stat in body:
            if stat.priority == 0 or stat.priority == 100: continue
            if 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match: continue

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            
            # Whitelist Victim
            if ip_dst in self.blocked_ips:
                if self.blocked_ips[ip_dst]['victim'] == ip_src:
                    continue 

            ip_proto = stat.match.get('ip_proto', 0)
            
            # Summary
            if ip_proto == 1: self.traffic_summary['ICMP'] += 1
            elif ip_proto == 6: self.traffic_summary['TCP'] += 1
            elif ip_proto == 17: self.traffic_summary['UDP'] += 1
            self.traffic_summary['Total'] += 1

            # Delta Rate Calculation
            packet_count = stat.packet_count
            byte_count = stat.byte_count
            flow_key = (ev.msg.datapath.id, ip_src, ip_dst, ip_proto)
            
            if flow_key in self.flow_history:
                last_pkts, last_bytes, last_ts = self.flow_history[flow_key]
                delta_pkts = packet_count - last_pkts
                delta_bytes = byte_count - last_bytes
                delta_time = current_time - last_ts
            else:
                delta_pkts = packet_count
                delta_bytes = byte_count
                delta_time = stat.duration_sec + (stat.duration_nsec / 1e9)
            
            self.flow_history[flow_key] = (packet_count, byte_count, current_time)
            if delta_time < 0.1: delta_time = 0.1
            
            pps_rate = delta_pkts / delta_time
            bps_rate = delta_bytes / delta_time

            icmp_type = 8 if ip_proto == 1 else 0
            icmp_code = 0
            flags = 0
            
            if pps_rate < 50: continue

            features = np.array([[
                ip_proto, icmp_code, icmp_type, 
                stat.duration_sec, stat.duration_nsec,
                0, 0, flags, 
                packet_count, byte_count,
                pps_rate, 0, bps_rate, 0
            ]])

            action_status = "ALLOW"
            
            if self.model:
                try:
                    features_scaled = self.scaler.transform(features)
                    prediction = self.model.predict(features_scaled)[0]
                    
                    is_attack = False
                    if prediction == 1:
                        is_attack = True
                    elif pps_rate > 500: # Fallback Threshold
                        is_attack = True
                        action_status = "FALLBACK_BLOCK"

                    if is_attack:
                        print(f"\n[ALERT] Blocked: {ip_src} -> {ip_dst} | Rate: {pps_rate:.0f} PPS")
                        self._block_ip(ev.msg.datapath, ip_src, ip_dst, ip_proto)
                        self._log_attack(ip_src, ip_dst, ip_proto, packet_count)
                        action_status = "BLOCKED"
                        
                    self._write_debug_log(ip_src, ip_dst, ip_proto, pps_rate, features[0], prediction, action_status)

                except Exception as e:
                    print(f"Error: {e}")

    def _update_offender_history(self, ip_src, proto):
        """Hàm cập nhật lịch sử vi phạm của IP"""
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        proto_name = proto_map.get(proto, 'UNKNOWN')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 1. Cập nhật bộ nhớ đệm (In-memory)
        if ip_src not in self.offender_history:
            self.offender_history[ip_src] = {
                'block_count': 0,
                'attack_methods': set(), # Dùng set để không trùng lặp
                'last_seen': timestamp
            }
        
        self.offender_history[ip_src]['block_count'] += 1
        self.offender_history[ip_src]['attack_methods'].add(proto_name)
        self.offender_history[ip_src]['last_seen'] = timestamp

        # 2. Lưu vào file CSV (Persistence)
        try:
            # Tạo list data để lưu
            data_list = []
            for ip, info in self.offender_history.items():
                methods_str = "+".join(list(info['attack_methods'])) # VD: TCP+UDP
                data_list.append({
                    'Attacker_IP': ip,
                    'Total_Blocks': info['block_count'],
                    'Attack_Methods': methods_str,
                    'Last_Seen': info['last_seen']
                })
            
            df = pd.DataFrame(data_list)
            # Tạo thư mục nếu chưa có
            if not os.path.exists(os.path.dirname(self.HISTORY_FILE)):
                os.makedirs(os.path.dirname(self.HISTORY_FILE))
            
            df.to_csv(self.HISTORY_FILE, index=False)
        except Exception as e:
            print(f"History Save Error: {e}")

    def _block_ip(self, datapath, ip_src, ip_dst, proto):
        current_time = datetime.now().timestamp()
        
        # Nếu đã bị chặn và còn hạn -> Bỏ qua
        if ip_src in self.blocked_ips:
            if current_time < self.blocked_ips[ip_src]['unlock_time']:
                return 

        # --- [GỌI HÀM CẬP NHẬT LỊCH SỬ] ---
        self._update_offender_history(ip_src, proto)

        self.blocked_ips[ip_src] = {
            'unlock_time': current_time + self.BLOCK_DURATION,
            'victim': ip_dst,
            'proto': proto
        }
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                match=match, instructions=inst,
                                idle_timeout=self.BLOCK_DURATION, 
                                hard_timeout=self.BLOCK_DURATION)
        datapath.send_msg(mod)
        print(f"-> Rule Installed for {ip_src} (Total Blocks: {self.offender_history[ip_src]['block_count']})")

    def _write_debug_log(self, src, dst, proto, rate, features, pred, action):
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            feat_str = "|".join([f"{x:.1f}" for x in features])
            line = f"{timestamp},{src},{dst},{proto},{rate:.0f},[{feat_str}],{pred},{action}\n"
            with open(self.DEBUG_FILE, "a") as f:
                f.write(line)
        except: pass

    def _log_attack(self, src, dst, proto, pkts):
        try:
            log_filename = '../attack_log/attack_logs.csv'
            if not os.path.exists(os.path.dirname(log_filename)): os.makedirs(os.path.dirname(log_filename))
            log_df = pd.DataFrame([{
                'timestamp': datetime.now().timestamp(),
                'ip_src': src, 'ip_dst': dst, 'ip_proto': proto,
                'packet_count': pkts, 'label': 'Attack'
            }])
            header = not os.path.exists(log_filename)
            log_df.to_csv(log_filename, mode='a', header=header, index=False)
        except: pass

    def _print_network_status(self):
        os.system('cls' if os.name == 'nt' else 'clear') 
        now = datetime.now().strftime('%H:%M:%S')
        print(f"\n{'='*65}")
        print(f"SDN MONITOR - {now} - Active Flows: {self.traffic_summary['Total']}")
        
        if self.blocked_ips:
            print(f"\n[ CURRENTLY BLOCKED IPs ]")
            current_ts = datetime.now().timestamp()
            for ip, data in self.blocked_ips.items():
                rem = int(data['unlock_time'] - current_ts)
                if rem > 0:
                    print(f"  > {ip:<15} (Victim: {data['victim']}) | Unblock in: {rem}s")
        
        # [PHẦN HIỂN THỊ LỊCH SỬ]
        if self.offender_history:
            print(f"\n[ REPEAT OFFENDERS HISTORY ]")
            print(f"{'Attacker IP':<16} | {'Blocks':<6} | {'Methods':<12} | {'Last Seen'}")
            print("-" * 65)
            # Sắp xếp theo số lần chặn giảm dần
            sorted_history = sorted(self.offender_history.items(), key=lambda x: x[1]['block_count'], reverse=True)
            for ip, info in sorted_history[:5]: # Chỉ hiện Top 5
                methods = ",".join(list(info['attack_methods']))
                print(f"{ip:<16} | {info['block_count']:<6} | {methods:<12} | {info['last_seen']}")