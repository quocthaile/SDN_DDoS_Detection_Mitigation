# ### IMPORT CÁC THƯ VIỆN CẦN THIẾT ###
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
import shutil

class SimpleMonitor13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        
        self.ENABLE_AI_PREDICT_LOG = True 
        self.STATUS_INTERVAL = 1.0
        
        # ==========================================
        # [CẤU HÌNH NGƯỠNG ĐỊNH LƯỢNG - TUNING AREA]
        # ==========================================
        
        # 1. Ngưỡng cơ bản
        self.MIN_PPS_THRESHOLD = 150         # Dưới mức này là nhiễu, bỏ qua
        self.VOLUMETRIC_THRESHOLD = 4000     # Trên mức này là Flood, chặn cứng
        
        # 2. Ngưỡng AI
        self.AI_CONFIDENCE_THRESHOLD = 0.75  # Ngưỡng chặn của AI
        self.AI_HIGH_CONFIDENCE = 0.99       # Ngưỡng AI chắc chắn tuyệt đối (để hiện lý do High PPS)
        self.AI_WARNING_THRESHOLD = 0.5      # Ngưỡng cảnh báo
        
        # 3. Whitelist (Bảo vệ Video 4K/File)
        self.WHITELIST_PKT_SIZE = 1000       # Gói tin > 1000 Bytes -> Luôn cho qua
        
        # 4. Blacklist Logic (Luật chặn cứng dựa trên hành vi)
        # Rule 2b: UDP Small Flood
        self.UDP_FLOOD_PPS = 1000            # Tốc độ tối thiểu để xét
        self.UDP_FLOOD_SIZE = 100            # Kích thước tối đa để xét (nhỏ hơn mức này là dính)
        
        # Rule 2c: TCP SYN Flood
        self.SYN_FLOOD_PPS = 300             # SYN Flood thường cần ít PPS hơn UDP để gây hại
        self.SYN_FLOOD_SIZE = 120            # Gói SYN thường rất nhỏ
        
        # 5. Timer
        self.PRED_LOCK_SECONDS = 3           # Thời gian giữ hiển thị trên CLI
        
        # ==========================================
        
        self.firewall_enabled = True 
        
        self.mac_to_port = {}
        self.datapaths = {}
        
        self.monitor_thread = hub.spawn(self._monitor)
        
        self.blocked_ips = {}           
        self.flow_history = {} 
        self.traffic_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        self.switch_stats = {}
        self.active_flow_stats = {}
        
        self.latest_pred = {
            'src': '-', 'dst': '-', 'proto': '-', 
            'rate': 0, 'result': 'IDLE', 'conf': '-', 'reason': '-',
            'priority': -1
        }
        self.pred_lock_until = 0
        self.pred_lock_priority = -1
        
        # --- CẤU HÌNH ĐƯỜNG DẪN ---
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../attack_log"))
        
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)

        self.HISTORY_FILE = os.path.join(LOG_DIR, "offender_history.csv")
        self.DDOS_DATASET_FILE = os.path.join(LOG_DIR, "ddos_captured_dataset.csv")
        self.MANUAL_BLOCK_FILE = os.path.join(LOG_DIR, "manual_blocks.txt")
        self.ATTACK_LOG_FILE = os.path.join(LOG_DIR, "attack_logs.csv")
        self.AI_PREDICT_LOG_FILE = os.path.join(LOG_DIR, "ai_predict.csv")
        self.TRAFFIC_MONITOR_FILE = os.path.join(LOG_DIR, "traffic_monitor.csv")
        self.DEBUG_FILE = "debug_ai_prediction.log"
        self.FIREWALL_STATUS_FILE = os.path.join(LOG_DIR, "firewall_status.txt")
        
        self.offender_history = {}
        self._load_offender_history()
        
        self._init_files()
        self._init_traffic_monitor()
        self._init_firewall_status()

        print("Loading AI Model...")
        try:
            model_path = os.path.join(BASE_DIR, '../models/rf_model.pkl')
            scaler_path = os.path.join(BASE_DIR, '../models/scaler.pkl')
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

    def _load_offender_history(self):
        if os.path.exists(self.HISTORY_FILE):
            try:
                if os.path.getsize(self.HISTORY_FILE) > 0:
                    df = pd.read_csv(self.HISTORY_FILE)
                    for _, row in df.iterrows():
                        ip = str(row['Attacker_IP'])
                        count = int(row['Total_Blocks'])
                        m_str = str(row['Attack_Methods'])
                        methods = set(m_str.split('+')) if m_str else set()
                        self.offender_history[ip] = {'count': count, 'methods': methods, 'last': row['Last_Seen']}
                    print(f"-> Loaded history for {len(self.offender_history)} IPs.")
            except Exception as e:
                print(f"Error loading history: {e}")

    def _init_traffic_monitor(self):
        with open(self.TRAFFIC_MONITOR_FILE, "w") as f:
            f.write("Timestamp,Blocked_MBps,Allowed_Attack_MBps,Benign_MBps\n")
        try: os.chmod(self.TRAFFIC_MONITOR_FILE, 0o666)
        except: pass

    def _init_files(self):
        if not os.path.exists(self.DDOS_DATASET_FILE):
            cols = [
                "timestamp", "datapath_id", "flow_id", "ip_src", "tp_src", 
                "ip_dst", "tp_dst", "ip_proto", "icmp_code", "icmp_type", 
                "flow_duration_sec", "flow_duration_nsec", "idle_timeout", "hard_timeout", 
                "flags", "packet_count", "byte_count", 
                "packet_count_per_second", "packet_count_per_nsecond", 
                "byte_count_per_second", "byte_count_per_nsecond", "label"
            ]
            with open(self.DDOS_DATASET_FILE, "w") as f:
                f.write(",".join(cols) + "\n")
            try: os.chmod(self.DDOS_DATASET_FILE, 0o666)
            except: pass

        if self.ENABLE_AI_PREDICT_LOG and not os.path.exists(self.AI_PREDICT_LOG_FILE):
            headers = "Timestamp,SrcIP,DstIP,Proto,PPS,AI_Prob_Normal,AI_Prob_Attack,Verdict,Action,Reason\n"
            with open(self.AI_PREDICT_LOG_FILE, "w") as f:
                f.write(headers)
            try: os.chmod(self.AI_PREDICT_LOG_FILE, 0o666)
            except: pass

    def _init_firewall_status(self):
        if not os.path.exists(self.FIREWALL_STATUS_FILE):
            with open(self.FIREWALL_STATUS_FILE, "w") as f:
                f.write("ON")
            try: os.chmod(self.FIREWALL_STATUS_FILE, 0o666)
            except: pass

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    # [PACKET_IN] Smart Flow Matching
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

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            if self.firewall_enabled and src_ip in self.blocked_ips:
                return 

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
            match_kwargs = {
                'in_port': in_port, 'eth_dst': dst, 'eth_src': src,
                'eth_type': ether_types.ETH_TYPE_IP,
                'ipv4_src': ip_pkt.src, 'ipv4_dst': ip_pkt.dst,
                'ip_proto': ip_pkt.proto
            }
            
            # [SMART MATCHING] Bắt cổng dịch vụ (Service Ports)
            SERVICE_PORTS = [80, 443, 8080]
            
            if ip_pkt.proto == 1:
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt: match_kwargs['icmpv4_type'] = icmp_pkt.type       
            elif ip_pkt.proto == 6: # TCP
                t = pkt.get_protocol(tcp.tcp)
                if t:
                    if t.dst_port in SERVICE_PORTS:
                        match_kwargs['tcp_dst'] = t.dst_port
                    elif t.src_port in SERVICE_PORTS:
                        match_kwargs['tcp_src'] = t.src_port
                        
            elif ip_pkt.proto == 17: # UDP
                u = pkt.get_protocol(udp.udp)
                if u:
                    if u.dst_port in SERVICE_PORTS:
                        match_kwargs['udp_dst'] = u.dst_port
                    elif u.src_port in SERVICE_PORTS:
                        match_kwargs['udp_src'] = u.src_port

            match = parser.OFPMatch(**match_kwargs)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id)
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
            if datapath.id in self.switch_stats:
                del self.switch_stats[datapath.id]

    def _clear_all_blocks(self):
        print("!!! FIREWALL DISABLED: Clearing all Drop Rules !!!")
        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=1000
            )
            datapath.send_msg(mod)
            datapath.send_msg(parser.OFPBarrierRequest(datapath))

    def _check_firewall_file(self):
        try:
            if os.path.exists(self.FIREWALL_STATUS_FILE):
                with open(self.FIREWALL_STATUS_FILE, "r") as f:
                    content = f.read().strip().upper()
                new_state = (content == "ON")
                if self.firewall_enabled and not new_state:
                    self.firewall_enabled = False
                    self.blocked_ips.clear()
                    self._clear_all_blocks()
                elif not self.firewall_enabled and new_state:
                    self.firewall_enabled = True
                    print("!!! FIREWALL ENABLED !!!")
        except Exception as e:
            print(f"Error checking firewall status: {e}")

    def _monitor(self):
        while True:
            self._check_firewall_file()
            
            if not os.path.exists(self.HISTORY_FILE) and len(self.offender_history) > 0:
                self.offender_history = {} 

            current_ts = datetime.now().timestamp()
            expired_ips = [ip for ip, data in self.blocked_ips.items() if current_ts > data['unlock_time']]
            for ip in expired_ips:
                del self.blocked_ips[ip]

            if time.time() >= self.pred_lock_until:
                self.pred_lock_priority = -1
                self.latest_pred['priority'] = -1
            
            for dp in self.datapaths.values():
                self._request_stats(dp)
                if self.firewall_enabled:
                    self._check_manual_blocks(dp)
            
            time.sleep(1.0)
            
            monitor_ts = time.time()
            total_blocked = 0.0
            total_allowed_attack = 0.0
            total_benign = 0.0
            
            for key in list(self.active_flow_stats.keys()):
                info = self.active_flow_stats[key]
                if monitor_ts - info['ts'] > 3.0:
                    del self.active_flow_stats[key]
                else:
                    if info['type'] == 'Blocked': total_blocked += info['rate']
                    elif info['type'] == 'Allowed_Attack': total_allowed_attack += info['rate']
                    else: total_benign += info['rate']

            try:
                ts_str = datetime.now().strftime('%H:%M:%S')
                if not os.path.exists(self.TRAFFIC_MONITOR_FILE):
                    with open(self.TRAFFIC_MONITOR_FILE, "w") as f:
                        f.write("Timestamp,Blocked_MBps,Allowed_Attack_MBps,Benign_MBps\n")
                
                with open(self.TRAFFIC_MONITOR_FILE, "a") as f:
                    f.write(f"{ts_str},{total_blocked:.4f},{total_allowed_attack:.4f},{total_benign:.4f}\n")
                    f.flush()
                    os.fsync(f.fileno())
            except: pass

            self._print_dashboard()

    def _check_manual_blocks(self, datapath):
        if not os.path.exists(self.MANUAL_BLOCK_FILE): return
        ips_to_block = []
        try:
            with open(self.MANUAL_BLOCK_FILE, "r") as f:
                lines = f.readlines()
            if lines:
                for line in lines:
                    ip = line.strip()
                    if ip: ips_to_block.append(ip)
                with open(self.MANUAL_BLOCK_FILE, "w") as f: f.write("")
        except: return

        for ip in ips_to_block:
            if ip not in self.blocked_ips:
                self._block_ip(datapath, ip, "Manual-Block", 0, reason="Manual-Block")

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _get_attack_reason(self, proto, pps):
        if pps < self.MIN_PPS_THRESHOLD: return "Normal Traffic"
        if proto == 17: return "UDP Volumetric Flood"
        if proto == 6: return "TCP SYN Flood"
        if proto == 1: return "ICMP Echo Flood"
        return f"High Packet Rate ({int(pps)} pps)"

    def _log_full_dataset(self, dpid, src, dst, proto, stat, pps, bps, label):
        try:
            timestamp = datetime.now().timestamp()
            pps_nsec = pps / 1e9 if pps > 0 else 0
            bps_nsec = bps / 1e9 if bps > 0 else 0
            icmp_code = stat.match.get('icmpv4_code') or 0
            icmp_type = stat.match.get('icmpv4_type') or 0
            flow_id = f"{src}-{dst}-{proto}"
            row = [
                timestamp, dpid, flow_id, src, 0, dst, 0, proto,
                icmp_code, icmp_type, stat.duration_sec, stat.duration_nsec,
                stat.idle_timeout, stat.hard_timeout, 0, stat.packet_count, stat.byte_count,
                f"{pps:.2f}", f"{pps_nsec:.9f}", f"{bps:.2f}", f"{bps_nsec:.9f}", label
            ]
            with open(self.DDOS_DATASET_FILE, "a") as f:
                f.write(",".join(map(str, row)) + "\n")
        except: pass

    # [CRITICAL FIX] Thêm try-except trong vòng lặp để tránh crash hệ thống
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        local_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        current_time = time.time()

        for stat in body:
            try: # [FIX] Bảo vệ vòng lặp
                if stat.priority == 0: continue
                ip_proto = stat.match.get('ip_proto', 0)
                
                # [FIX] Đếm Total Flows ngay từ đầu
                if ip_proto == 1: local_summary['ICMP'] += 1
                elif ip_proto == 6: local_summary['TCP'] += 1
                elif ip_proto == 17: local_summary['UDP'] += 1
                local_summary['Total'] += 1

                # 1. Xử lý các Flow đang bị BLOCK
                if stat.priority >= 100:
                    src_key = stat.match.get('ipv4_src', '0.0.0.0')
                    dst_key = 'BLOCK'
                    
                    packet_count = stat.packet_count
                    byte_count = stat.byte_count
                    
                    flow_key = (dpid, src_key, dst_key, ip_proto, stat.priority)
                    mbps_current = 0
                    if flow_key in self.flow_history:
                        last_pkts, last_bytes, last_ts = self.flow_history[flow_key]
                        dt = current_time - last_ts
                        if 0.1 < dt < 3.0:
                            mbps_current = ((byte_count - last_bytes) * 8) / dt / 1000000
                    self.flow_history[flow_key] = (packet_count, byte_count, current_time)
                    
                    src_ip = stat.match.get('ipv4_src')
                    current_label = '1'
                    if src_ip in self.blocked_ips:
                        if self.blocked_ips[src_ip].get('reason') == "Manual-Block":
                            current_label = 'MANUALBLOCK'
                    dst_ip = stat.match.get('ipv4_dst', '0.0.0.0')
                    
                    self._log_full_dataset(dpid, src_ip, dst_ip, ip_proto, stat, 0, 0, current_label)
                    self.active_flow_stats[flow_key] = {'rate': mbps_current, 'type': 'Blocked', 'ts': current_time}
                    continue 

                # 2. Xử lý Flow thường (Benign / Monitor)
                src_key = stat.match.get('ipv4_src', '0.0.0.0')
                dst_key = stat.match.get('ipv4_dst', '0.0.0.0')
                packet_count = stat.packet_count
                byte_count = stat.byte_count
                flow_key = (dpid, src_key, dst_key, ip_proto, stat.priority)
                
                pps_rate = 0
                bps_rate = 0
                mbps_current = 0
                
                if flow_key in self.flow_history:
                    last_pkts, last_bytes, last_ts = self.flow_history[flow_key]
                    delta_pkts = packet_count - last_pkts
                    delta_bytes = byte_count - last_bytes
                    delta_time = current_time - last_ts
                    
                    if delta_time > 0.1 and delta_time < 3.0: 
                        if delta_pkts >= 0:
                            pps_rate = delta_pkts / delta_time
                            bps_rate = delta_bytes / delta_time
                            mbps_current = (bps_rate * 8) / 1000000
                
                self.flow_history[flow_key] = (packet_count, byte_count, current_time)

                traffic_type = 'Benign'
                
                # Bỏ qua ICMP control messages
                icmp_type_stat = stat.match.get('icmpv4_type')
                if ip_proto == 1 and icmp_type_stat == 0:
                    self.active_flow_stats[flow_key] = {'rate': mbps_current, 'type': 'Benign', 'ts': current_time}
                    continue

                if 'ipv4_src' not in stat.match: 
                    self.active_flow_stats[flow_key] = {'rate': mbps_current, 'type': 'Benign', 'ts': current_time}
                    continue
                    
                ip_src = stat.match['ipv4_src']
                ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
                if ip_dst in self.blocked_ips: continue

                if pps_rate >= self.MIN_PPS_THRESHOLD: # > 150 PPS
                    avg_pkt_size = bps_rate / pps_rate if pps_rate > 0 else 0
                    
                    # BƯỚC 1: AI PREDICT
                    icmp_type = 8 if ip_proto == 1 else 0; icmp_code = 0; flags = 0
                    features = np.array([[ip_proto, icmp_code, icmp_type, stat.duration_sec, stat.duration_nsec, 0, 0, flags, packet_count, byte_count, pps_rate, 0, bps_rate, 0]])
                    ai_conf_score = 0.0; ai_verdict = "Normal"
                    
                    if self.model:
                        try:
                            features_scaled = self.scaler.transform(features)
                            probs = self.model.predict_proba(features_scaled)[0]
                            ai_conf_score = probs[1]
                            if ai_conf_score >= self.AI_CONFIDENCE_THRESHOLD: ai_verdict = "AI_ATTACK"
                        except: pass

                    # BƯỚC 2: RA QUYẾT ĐỊNH
                    final_action = "MONITOR"
                    reason = f"Safe (Conf: {ai_conf_score:.2f})"
                    display_priority = 1
                    
                    # [WHITELIST] Server Protection
                    tp_src = stat.match.get('tcp_src') or stat.match.get('udp_src') or 0
                    if tp_src in [80, 443, 8080]:
                        final_action = "ALLOW"
                        reason = f"Server Response (Port {tp_src})"
                        display_priority = 2
                        traffic_type = 'Benign'
                        
                    # Rule 1: Chặn cứng Volumetric
                    elif pps_rate > self.VOLUMETRIC_THRESHOLD:
                        final_action = "BLOCK"
                        reason = f"Volumetric > {self.VOLUMETRIC_THRESHOLD}pps"
                        display_priority = 3
                    
                    # Rule 2: Whitelist Video/File
                    elif avg_pkt_size > self.WHITELIST_PKT_SIZE:
                        final_action = "ALLOW"
                        reason = f"Whitelist: Large Pkt ({int(avg_pkt_size)}B)"
                        display_priority = 2
                        traffic_type = 'Benign'

                    # Rule 2b: Chặn UDP giả dạng
                    elif ip_proto == 17 and pps_rate > self.UDP_FLOOD_PPS and avg_pkt_size < self.UDP_FLOOD_SIZE:
                        final_action = "BLOCK"
                        reason = f"Small UDP Flood ({int(avg_pkt_size)}B)"
                        display_priority = 3

                    # Rule 2c: Chặn TCP SYN Flood
                    elif ip_proto == 6 and pps_rate > self.SYN_FLOOD_PPS and avg_pkt_size < self.SYN_FLOOD_SIZE:
                        final_action = "BLOCK"
                        reason = f"TCP SYN Flood Detect ({int(avg_pkt_size)}B)"
                        display_priority = 3

                    # [UPDATED] Rule 3: AI Chặn (Reason chỉnh sửa & Sử dụng biến ngưỡng)
                    elif ai_verdict == "AI_ATTACK":
                        final_action = "BLOCK"
                        if ai_conf_score > self.AI_HIGH_CONFIDENCE: # > 0.99
                             reason = f"AI Detect + High PPS (Conf: {ai_conf_score:.2f})"
                        else:
                             reason = f"AI Detected (Conf: {ai_conf_score:.2f})"
                        display_priority = 3

                    # Rule 4: Warning
                    elif ai_conf_score > self.AI_WARNING_THRESHOLD:
                        final_action = "WARNING"
                        reason = f"Suspicious (Conf: {ai_conf_score:.2f})"
                        display_priority = 2

                    # BƯỚC 3: THỰC THI
                    if final_action == "BLOCK":
                        if self.firewall_enabled:
                            traffic_type = 'Blocked'
                            self._block_ip(ev.msg.datapath, ip_src, ip_dst, ip_proto, reason=reason)
                            self._log_attack(ip_src, ip_dst, ip_proto, packet_count, label="Attack", reason=reason)
                        else:
                            traffic_type = 'Allowed_Attack'
                            self._log_attack(ip_src, ip_dst, ip_proto, packet_count, label="Passive Detect", reason=f"[FW-OFF] {reason}")

                    elif final_action == "WARNING":
                        log_label = "Warning" if self.firewall_enabled else "Passive Warning"
                        self._log_attack(ip_src, ip_dst, ip_proto, packet_count, label=log_label, reason=reason)
                        if not self.firewall_enabled:
                            traffic_type = 'Allowed_Attack'

                    # BƯỚC 4: CẬP NHẬT CLI DASHBOARD
                    now_ts = time.time()
                    if (now_ts >= self.pred_lock_until) or (display_priority >= self.pred_lock_priority):
                        result_str = "NORMAL"
                        if final_action == "BLOCK": result_str = "ATTACK"
                        elif final_action == "WARNING": result_str = "WARNING"
                        elif final_action == "ALLOW": result_str = "NORMAL"

                        self.latest_pred = {
                            'src': ip_src, 'dst': ip_dst, 'proto': ip_proto,
                            'rate': f"{pps_rate:.0f}",
                            'result': result_str,
                            'conf': f"{ai_conf_score:.2f}",
                            'reason': reason,
                            'priority': display_priority
                        }
                        self.pred_lock_until = now_ts + (self.PRED_LOCK_SECONDS if display_priority > 1 else 0.5)
                        self.pred_lock_priority = display_priority

                self.active_flow_stats[flow_key] = {'rate': mbps_current, 'type': traffic_type, 'ts': current_time}
            
            except Exception as e:
                continue
        
        self.switch_stats[dpid] = local_summary
        total = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        for stats in self.switch_stats.values():
            total['TCP'] += stats.get('TCP', 0)
            total['UDP'] += stats.get('UDP', 0)
            total['ICMP'] += stats.get('ICMP', 0)
            total['Total'] += stats.get('Total', 0)
        self.traffic_summary = total

    def _log_ai_prediction(self, src, dst, proto, pps, probs, verdict, action, reason):
        if not self.ENABLE_AI_PREDICT_LOG: return
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            prob_normal = f"{probs[0]:.2f}"
            prob_attack = f"{probs[1]:.2f}"
            line = f"{timestamp},{src},{dst},{proto},{pps:.0f},{prob_normal},{prob_attack},{verdict},{action},{reason}\n"
            with open(self.AI_PREDICT_LOG_FILE, "a") as f: f.write(line)
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

    def _block_ip(self, datapath, ip_src, ip_dst, proto, reason="Unknown"):
        current_time = datetime.now().timestamp()
        if ip_src in self.blocked_ips:
            if current_time < self.blocked_ips[ip_src]['unlock_time']: return 
        
        # [FIX GHOST TRAFFIC] Xóa ngay lập tức mọi dữ liệu cũ
        keys_to_remove = [k for k in self.flow_history if k[1] == ip_src]
        for k in keys_to_remove: del self.flow_history[k]
        
        keys_to_remove_active = [k for k in self.active_flow_stats if k[1] == ip_src]
        for k in keys_to_remove_active: del self.active_flow_stats[k]

        self._update_offender_history(ip_src, proto)
        offense_count = self.offender_history[ip_src]['count']
        if offense_count == 1: duration = 30
        elif offense_count == 2: duration = 60
        else: duration = 120
        self.blocked_ips[ip_src] = {
            'unlock_time': current_time + duration,
            'victim': ip_dst, 
            'proto': proto,
            'duration': duration,
            'reason': reason
        }
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
        mod_del = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod_del)
        datapath.send_msg(parser.OFPBarrierRequest(datapath))
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        mod_add = parser.OFPFlowMod(
            datapath=datapath, 
            priority=1000, 
            match=match, 
            instructions=inst,
            idle_timeout=duration, 
            hard_timeout=duration
        )
        datapath.send_msg(mod_add)

    def _write_debug_log(self, src, dst, proto, rate, reason, result, action):
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            line = f"{timestamp},{src},{dst},{proto},{rate:.0f},{reason},{result},{action}\n"
            with open(self.DEBUG_FILE, "a") as f: f.write(line)
        except: pass

    def _print_dashboard(self):
        sys.stdout.write("\033[H\033[J")
        now = datetime.now().strftime('%H:%M:%S')
        W = 110; IW = W - 4
        def h_line(char='═'): print(f"╠{char*(W-2)}╣")
        def p_line(text):
            visual_offset = 1 if "🚫" in text else 0
            padding_len = IW - len(text) - visual_offset
            if padding_len < 0: padding_len = 0
            print(f"║ {text}{' ' * padding_len} ║")
        def p_alert_line(label, info_text, color_code):
            raw_text = f"[{label}] {info_text}"
            padding = IW - len(raw_text)
            if padding < 0: padding = 0
            print(f"║ {color_code}[{label}]\033[0m {info_text}{' ' * padding} ║")

        print(f"╔{'═'*(W-2)}╗")
        fw_status = "ON" if self.firewall_enabled else "OFF"
        title = f"SDN AI-GUARD [FW: {fw_status}]"; time_str = f"Time: {now}"
        gap = IW - len(title) - len(time_str)
        if gap < 0: gap = 1
        print(f"║ {title}{' '*gap}{time_str} ║")
        h_line()
        
        p_line("SYSTEM STATUS")
        stats_msg = f"> Total Flows: {self.traffic_summary['Total']} (ICMP:{self.traffic_summary['ICMP']} TCP:{self.traffic_summary['TCP']} UDP:{self.traffic_summary['UDP']})"
        p_line(stats_msg)
        h_line()
        
        if not self.firewall_enabled:
            p_alert_line("MONITORING", "Firewall OFF - Passive Detection Mode", "\033[93m")
            h_line()
        
        p = self.latest_pred
        res = p['result']
        p_line("REAL-TIME INSPECTION (AI + Rule Hybrid)")
        p_line(f"Source: {p['src']:<15}  ->  Dest: {p['dst']:<15}")
        
        if res == "ATTACK":
            info = f"PPS: {p['rate']} | Conf: {p['conf']} | {p['reason']}"
            p_alert_line("ATTACK", info, "\033[91m") # RED
        elif res == "WARNING":
            info = f"PPS: {p['rate']} | Conf: {p['conf']} | {p['reason']}"
            p_alert_line("WARNING", info, "\033[93m") # YELLOW
        elif res == "NORMAL":
            if p['reason'] != '-':
                info = f"PPS: {p['rate']} | Conf: {p['conf']} | {p['reason']}"
            else:
                info = f"Proto: {p['proto']} | Rate: {p['rate']} pps"
            p_alert_line("NORMAL", info, "\033[92m") # GREEN
        else:
            p_line(f"[IDLE] Waiting for traffic > {self.MIN_PPS_THRESHOLD} pps...")
            
        h_line()
        
        if self.firewall_enabled:
            p_line("CURRENTLY BLOCKED (Mitigation Active)")
            if not self.blocked_ips:
                p_line("[ No active threats blocked ]")
            else:
                current_ts = datetime.now().timestamp()
                count = 0
                header = f"   {'IP Address':<15} | {'Time Left':<9} | {'Proto':<5} | {'Reason'}"
                p_line(header)
                p_line("-" * (IW-2))
                for ip, data in self.blocked_ips.items():
                    if count >= 5:
                        p_line(f"... (+{len(self.blocked_ips)-5} others)")
                        break
                    rem = int(data['unlock_time'] - current_ts)
                    duration = data.get('duration', 60)
                    reason = data.get('reason', 'Unknown')
                    proto_num = data.get('proto', 0)
                    proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 0: 'ALL'}
                    proto_str = proto_map.get(proto_num, str(proto_num))
                    if len(reason) > 50: reason = reason[:47] + "..."
                    if rem > 0:
                        time_display = f"{rem}s/{duration}s"
                        row = f"🚫 {ip:<15} | {time_display:<9} | {proto_str:<5} | {reason}"
                        p_line(row)
                        count += 1
            h_line()

        p_line("TOP OFFENDERS (History)")
        if not self.offender_history:
            p_line("[ No history yet ]")
        else:
            p_line(f"{'No.':<4}{'IP Address':<18}{'Blocks':<10}{'Methods':<15}{'Last Seen':<12}")
            p_line("-" * (IW-2))
            sorted_hist = sorted(self.offender_history.items(), key=lambda x: x[1]['count'], reverse=True)
            for i, (ip, info) in enumerate(sorted_hist[:5]):
                m = "+".join(list(info['methods']))
                last = info.get('last', '-')
                row = f"{i+1:<4}{ip:<18}{info['count']:<10}{m:<15}{last:<12}"
                p_line(row)
        print(f"╚{'═'*(W-2)}╝")