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
import stat

class SimpleMonitor13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        
        # --- [CẤU HÌNH] BẬT/TẮT LOG AI PREDICT TẠI ĐÂY ---
        self.ENABLE_AI_PREDICT_LOG = True 
        # -------------------------------------------------

        self.mac_to_port = {}
        self.datapaths = {}
        self.STATUS_INTERVAL = 1 
        self.monitor_thread = hub.spawn(self._monitor)

        self.BLOCK_DURATION = 60
        self.blocked_ips = {}           
        self.traffic_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        self.flow_history = {} 
        
        self.latest_pred = {
            'src': '-', 'dst': '-', 'proto': '-', 
            'rate': 0, 'result': 'Waiting...', 'conf': '-', 'reason': '-',
            'priority': -1
        }

        self.offender_history = {} 
        
        # --- PATH CONFIGURATION ---
        CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
        LOG_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "../attack_log"))
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)

        self.HISTORY_FILE = os.path.join(LOG_DIR, "offender_history.csv")
        self.DDOS_DATASET_FILE = os.path.join(LOG_DIR, "ddos_captured_dataset.csv")
        self.MANUAL_BLOCK_FILE = os.path.join(LOG_DIR, "manual_blocks.txt")
        self.ATTACK_LOG_FILE = os.path.join(LOG_DIR, "attack_logs.csv")
        
        # [MỚI] File log chi tiết AI Prediction
        self.AI_PREDICT_LOG_FILE = os.path.join(LOG_DIR, "ai_predict.csv")
        
        self.DEBUG_FILE = "debug_ai_prediction.log"
        
        self._init_files()
        self._init_debug_log()

        print("Loading AI Model...")
        try:
            model_path = os.path.join(CURRENT_DIR, '../models/rf_model.pkl')
            scaler_path = os.path.join(CURRENT_DIR, '../models/scaler.pkl')

            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                print("-> Model & Scaler loaded successfully!")
            else:
                self.model = None
                print(f"ERROR: Model not found at {model_path}")
        except Exception as e:
            print(f"ERROR loading model: {e}")
            self.model = None

    def _init_debug_log(self):
        with open(self.DEBUG_FILE, "w") as f:
            f.write("Timestamp,SrcIP,DstIP,Proto,Rate,Reason,Result,Action\n")

    def _init_files(self):
        # Init Dataset file
        if not os.path.exists(self.DDOS_DATASET_FILE):
            cols = [
                "Flow ID", "Source IP", "Src Port", "Destination IP", "Dst Port",
                "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets", 
                "Total Backward Packets", "Total Length of Fwd Packets", 
                "Total Length of Bwd Packets", "Fwd Packet Length Max", 
                "Fwd Packet Length Min", "Bwd Packet Length Max", "Bwd Packet Length Min",
                "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", 
                "Flow IAT Max", "Label"
            ]
            with open(self.DDOS_DATASET_FILE, "w") as f:
                f.write(",".join(cols) + "\n")
            try: os.chmod(self.DDOS_DATASET_FILE, 0o666)
            except: pass

        # [MỚI] Init AI Predict Log file
        if self.ENABLE_AI_PREDICT_LOG and not os.path.exists(self.AI_PREDICT_LOG_FILE):
            headers = "Timestamp,SrcIP,DstIP,Proto,PPS,AI_Prob_Normal,AI_Prob_Attack,Verdict,Action,Reason\n"
            with open(self.AI_PREDICT_LOG_FILE, "w") as f:
                f.write(headers)
            try: os.chmod(self.AI_PREDICT_LOG_FILE, 0o666)
            except: pass

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
                                    priority=priority, match=match, instructions=inst)
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
            current_ts = datetime.now().timestamp()
            expired_ips = [ip for ip, data in self.blocked_ips.items() if current_ts > data['unlock_time']]
            for ip in expired_ips:
                del self.blocked_ips[ip]

            if self.latest_pred['priority'] < 2:
                 self.latest_pred['priority'] = -1
                 
            for dp in self.datapaths.values():
                self._request_stats(dp)
                self._check_manual_blocks(dp)
            
            self._print_dashboard()
            time.sleep(self.STATUS_INTERVAL)

    def _check_manual_blocks(self, datapath):
        if not os.path.exists(self.MANUAL_BLOCK_FILE): return
        try:
            with open(self.MANUAL_BLOCK_FILE, "r") as f:
                lines = f.readlines()
            with open(self.MANUAL_BLOCK_FILE, "w") as f: f.write("")
            
            for line in lines:
                ip = line.strip()
                if ip and ip not in self.blocked_ips:
                    self._block_ip(datapath, ip, "Manual-Block", 0)
        except: pass

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _get_attack_reason(self, proto, pps):
        if pps < 50: return "Normal Traffic"
        if proto == 17: return "UDP Volumetric Flood" if pps > 1000 else "UDP Flood Pattern"
        if proto == 6: return "TCP SYN Flood" if pps > 1000 else "TCP Anomalous Rate"
        if proto == 1: return "ICMP Echo Flood"
        return f"High Packet Rate ({int(pps)} pps)"

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.traffic_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        current_time = time.time()

        for stat in body:
            if stat.priority == 0 or stat.priority == 100: continue
            if 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match: continue

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            
            if ip_dst in self.blocked_ips: continue

            ip_proto = stat.match.get('ip_proto', 0)
            
            if ip_proto == 1: self.traffic_summary['ICMP'] += 1
            elif ip_proto == 6: self.traffic_summary['TCP'] += 1
            elif ip_proto == 17: self.traffic_summary['UDP'] += 1
            self.traffic_summary['Total'] += 1

            packet_count = stat.packet_count
            byte_count = stat.byte_count
            flow_key = (ev.msg.datapath.id, ip_src, ip_dst, ip_proto)
            
            pps_rate = 0
            bps_rate = 0
            
            if flow_key in self.flow_history:
                last_pkts, last_bytes, last_ts = self.flow_history[flow_key]
                delta_pkts = packet_count - last_pkts
                delta_bytes = byte_count - last_bytes
                delta_time = current_time - last_ts
                
                if delta_time > 3.0: 
                    self.flow_history[flow_key] = (packet_count, byte_count, current_time)
                    continue 

                if delta_pkts < 0: 
                    delta_pkts = packet_count
                    delta_bytes = byte_count

                if delta_time < 0.1: delta_time = 0.1
                
                pps_rate = delta_pkts / delta_time
                bps_rate = delta_bytes / delta_time
            
            self.flow_history[flow_key] = (packet_count, byte_count, current_time)

            if pps_rate < 50: continue

            icmp_type = 8 if ip_proto == 1 else 0
            icmp_code = 0
            flags = 0

            features = np.array([[
                ip_proto, icmp_code, icmp_type, 
                stat.duration_sec, stat.duration_nsec,
                0, 0, flags, 
                packet_count, byte_count,
                pps_rate, 0, bps_rate, 0
            ]])

            action_status = "ALLOW"
            reason = self._get_attack_reason(ip_proto, pps_rate)
            verdict = "Normal"
            conf_score = 0.0
            probs = [1.0, 0.0] # Default
            display_priority = 0

            if self.model:
                try:
                    features_scaled = self.scaler.transform(features)
                    probs = self.model.predict_proba(features_scaled)[0] # [Prob_Normal, Prob_Attack]
                    conf_score = probs[1]
                    
                    if pps_rate < 50:
                        verdict = "Normal"
                        display_priority = 0
                    
                    is_attack = False
                    
                    if conf_score >= 0.8:
                        is_attack = True
                        reason = f"AI Detected ({reason})"
                    elif pps_rate > 500:
                        is_attack = True
                        reason = f"Volumetric Rate > 500 ({reason})"
                    
                    if is_attack:
                        verdict = "ATTACK"
                        action_status = "BLOCKED"
                        display_priority = 2
                        self._block_ip(ev.msg.datapath, ip_src, ip_dst, ip_proto)
                        self._log_attack(ip_src, ip_dst, ip_proto, packet_count, label="Attack", reason=reason)
                        self._log_full_dataset(ip_src, ip_dst, ip_proto, stat, pps_rate, bps_rate)
                    
                    elif pps_rate > 200:
                        verdict = "SUSPICIOUS"
                        action_status = "ALERT"
                        display_priority = 1
                        self._log_attack(ip_src, ip_dst, ip_proto, packet_count, label="Suspicious", reason=reason)

                    # [MỚI] Ghi log AI Predict (Tự động ghi mọi phán đoán)
                    self._log_ai_prediction(ip_src, ip_dst, ip_proto, pps_rate, probs, verdict, action_status, reason)

                    if display_priority >= self.latest_pred['priority']:
                        self.latest_pred = {
                            'src': ip_src, 'dst': ip_dst, 'proto': ip_proto,
                            'rate': f"{pps_rate:.0f}",
                            'result': verdict,
                            'conf': f"{conf_score:.2f}",
                            'reason': reason,
                            'priority': display_priority
                        }

                    self._write_debug_log(ip_src, ip_dst, ip_proto, pps_rate, reason, verdict, action_status)

                except Exception as e: pass

    # [MỚI] Hàm ghi log dự đoán AI chi tiết
    def _log_ai_prediction(self, src, dst, proto, pps, probs, verdict, action, reason):
        if not self.ENABLE_AI_PREDICT_LOG: return
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            prob_normal = f"{probs[0]:.2f}"
            prob_attack = f"{probs[1]:.2f}"
            
            line = f"{timestamp},{src},{dst},{proto},{pps:.0f},{prob_normal},{prob_attack},{verdict},{action},{reason}\n"
            
            with open(self.AI_PREDICT_LOG_FILE, "a") as f:
                f.write(line)
        except: pass

    def _log_full_dataset(self, src, dst, proto, stat, pps, bps):
        try:
            flow_id = f"{src}-{dst}-{proto}-0-0"
            timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            duration = stat.duration_sec + stat.duration_nsec/1e9
            row = [
                flow_id, src, "0", dst, "0", proto, timestamp, 
                f"{duration:.6f}", stat.packet_count, "0", 
                stat.byte_count, "0", "0", "0", "0", "0", 
                f"{bps:.2f}", f"{pps:.2f}", "0", "0", "0", "DDoS"
            ]
            with open(self.DDOS_DATASET_FILE, "a") as f:
                f.write(",".join(map(str, row)) + "\n")
        except: pass

    def _update_offender_history(self, ip_src, proto):
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        proto_name = proto_map.get(proto, 'UNK')
        timestamp = datetime.now().strftime('%H:%M:%S')
        if ip_src not in self.offender_history:
            self.offender_history[ip_src] = {'count': 0, 'methods': set(), 'last': timestamp}
        self.offender_history[ip_src]['count'] += 1
        self.offender_history[ip_src]['methods'].add(proto_name)
        self.offender_history[ip_src]['last'] = timestamp
        try:
            data_list = []
            for ip, info in self.offender_history.items():
                methods_str = "+".join(list(info['methods']))
                data_list.append({'Attacker_IP': ip, 'Total_Blocks': info['count'], 'Attack_Methods': methods_str, 'Last_Seen': info['last']})
            
            df = pd.DataFrame(data_list)
            df.to_csv(self.HISTORY_FILE, index=False)
            os.chmod(self.HISTORY_FILE, 0o666)
        except: pass

    def _block_ip(self, datapath, ip_src, ip_dst, proto):
        current_time = datetime.now().timestamp()
        
        if ip_src in self.blocked_ips:
            if current_time < self.blocked_ips[ip_src]['unlock_time']: return 

        keys_to_remove = [k for k in self.flow_history if k[1] == ip_src]
        for k in keys_to_remove:
            del self.flow_history[k]

        self._update_offender_history(ip_src, proto)
        self.blocked_ips[ip_src] = {
            'unlock_time': current_time + self.BLOCK_DURATION,
            'victim': ip_dst, 'proto': proto
        }
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst,
                                idle_timeout=self.BLOCK_DURATION, hard_timeout=self.BLOCK_DURATION)
        datapath.send_msg(mod)

    def _write_debug_log(self, src, dst, proto, rate, reason, result, action):
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            line = f"{timestamp},{src},{dst},{proto},{rate:.0f},{reason},{result},{action}\n"
            with open(self.DEBUG_FILE, "a") as f:
                f.write(line)
        except: pass

    def _log_attack(self, src, dst, proto, pkts, label="Attack", reason="Unknown"):
        try:
            log_df = pd.DataFrame([{
                'timestamp': datetime.now().timestamp(),
                'ip_src': src, 'ip_dst': dst, 'ip_proto': proto,
                'packet_count': pkts, 'label': label, 'reason': reason
            }])
            header = not os.path.exists(self.ATTACK_LOG_FILE)
            log_df.to_csv(self.ATTACK_LOG_FILE, mode='a', header=header, index=False)
            os.chmod(self.ATTACK_LOG_FILE, 0o666) 
        except: pass

    def _print_dashboard(self):
        sys.stdout.write("\033[H\033[J")
        now = datetime.now().strftime('%H:%M:%S')
        W = 75; IW = W - 4
        def h_line(char='═'): print(f"╠{char*(W-2)}╣")
        def p_line(text):
            visual_offset = 1 if "🚫" in text else 0
            padding_len = IW - len(text) - visual_offset
            if padding_len < 0: padding_len = 0
            print(f"║ {text}{' ' * padding_len} ║")
        def p_color_line(prefix, content, color, suffix):
            raw_text = f"{prefix}{content}{suffix}"
            padding = IW - len(raw_text)
            if padding < 0: padding = 0
            print(f"║ {prefix}{color}{content}\033[0m{suffix}{' '*padding} ║")

        print(f"╔{'═'*(W-2)}╗")
        title = "SDN AI-GUARD DASHBOARD v3.3 (AI-LOG)"; time_str = f"Time: {now}"
        gap = IW - len(title) - len(time_str)
        if gap < 0: gap = 1
        print(f"║ {title}{' '*gap}{time_str} ║")
        h_line()
        
        p_line("SYSTEM STATUS")
        stats_msg = f"> Total Flows: {self.traffic_summary['Total']} (ICMP:{self.traffic_summary['ICMP']} TCP:{self.traffic_summary['TCP']} UDP:{self.traffic_summary['UDP']})"
        p_line(stats_msg)
        h_line()
        
        p = self.latest_pred
        if p['result'] == "ATTACK": res_color = "\033[91m"
        elif p['result'] == "SUSPICIOUS": res_color = "\033[93m"
        else: res_color = "\033[92m"
        
        p_line("REAL-TIME INSPECTION (AI + Rule Hybrid)")
        p_line(f"src: {p['src']:<15} -> dst: {p['dst']:<15}")
        p_line(f"proto: {p['proto']:<6} | rate: {p['rate']:<8} pps")
        p_line(f"Reason: {p['reason']}")
        p_color_line("AI Verdict: ", f"{p['result']}", res_color, f" (Conf: {p['conf']})")
        h_line()

        p_line("CURRENTLY BLOCKED (Mitigation Active)")
        if not self.blocked_ips:
            p_line("[ No active threats blocked ]")
        else:
            current_ts = datetime.now().timestamp()
            count = 0
            for ip, data in self.blocked_ips.items():
                if count >= 3:
                    p_line(f"... (+{len(self.blocked_ips)-3} others)")
                    break
                rem = int(data['unlock_time'] - current_ts)
                if rem > 0:
                    row = f"🚫 {ip:<15} (Victim: {data['victim']:<15}) | {rem}s left"
                    p_line(row)
                    count += 1
        h_line()

        p_line("TOP OFFENDERS (History)")
        if not self.offender_history:
            p_line("[ No history yet ]")
        else:
            sorted_hist = sorted(self.offender_history.items(), key=lambda x: x[1]['count'], reverse=True)
            for i, (ip, info) in enumerate(sorted_hist[:3]):
                m = "+".join(list(info['methods']))
                row = f"{i+1}. {ip:<15} | Blocks: {info['count']:<4} | {m}"
                p_line(row)
        print(f"╚{'═'*(W-2)}╝")