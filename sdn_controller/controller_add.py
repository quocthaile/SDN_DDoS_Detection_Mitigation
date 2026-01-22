# ### IMPORT CÁC THƯ VIỆN CẦN THIẾT ###
# Ryu Framework: Dùng để giao tiếp với OpenFlow Switch
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
# Thư viện xử lý gói tin: Ethernet, IP, TCP, UDP, ICMP
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp, arp
# Thư viện Hub: Dùng để tạo luồng (thread) chạy song song (Greenlet)
from ryu.lib import hub
from datetime import datetime
# Pandas/Numpy: Xử lý dữ liệu bảng và tính toán số học
import pandas as pd
import numpy as np
# Joblib/Sklearn: Tải và chạy mô hình AI (Random Forest)
import joblib 
from sklearn.preprocessing import StandardScaler
import time
import os
import sys
import stat

# ### KHỞI TẠO CLASS CONTROLLER ###
# Kế thừa từ app_manager.RyuApp để Ryu nhận diện đây là một ứng dụng SDN
class SimpleMonitor13(app_manager.RyuApp):
    # Chỉ định phiên bản OpenFlow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        
        # --- [CẤU HÌNH] BẬT/TẮT LOG AI PREDICT TẠI ĐÂY ---
        # Biến này quyết định có ghi chi tiết từng dự đoán của AI ra file csv hay không.
        # True: Ghi log chi tiết (tốn dung lượng đĩa hơn nhưng tốt để debug).
        # False: Chỉ ghi log tấn công chính.
        self.ENABLE_AI_PREDICT_LOG = True 
        # -------------------------------------------------

        # Lưu bảng định tuyến MAC Address -> Port để chuyển mạch gói tin
        self.mac_to_port = {}
        # Lưu danh sách các Switch đang kết nối với Controller
        self.datapaths = {}
        
        # ### CẤU HÌNH CHU KỲ GIÁM SÁT (QUAN TRỌNG) ###
        # Thời gian (giây) giữa các lần gửi yêu cầu thống kê (Flow Stats Request).
        # - Giảm xuống (ví dụ 0.5): Phát hiện nhanh hơn, nhưng tăng tải CPU cho Controller và Switch.
        # - Tăng lên (ví dụ 5.0): Giảm tải hệ thống, nhưng phản ứng chậm với tấn công.
        self.STATUS_INTERVAL = 1 

        # ### CẤU HÌNH NGƯỎNG PPS NỀN (BASELINE) ###
        # Các flow có PPS thấp hơn ngưỡng này sẽ được coi là nền và bỏ qua để tiết kiệm CPU.
        self.MIN_PPS_THRESHOLD = 50

        # ### CẤU HÌNH THỜI GIAN KHÓA HIỂN THỊ CẢNH BÁO (CLI) ###
        # Khi phát hiện WARNING/ATTACK, giữ hiển thị trong vài giây để tránh bị ghi đè ngay lập tức.
        self.PRED_LOCK_SECONDS = 2
        
        # Tạo luồng riêng biệt để chạy hàm _monitor() liên tục mà không chặn luồng chính
        self.monitor_thread = hub.spawn(self._monitor)

        # ### CẤU HÌNH THỜI GIAN CHẶN (PUNISHMENT TIME) ###
        # [UPDATED] Biến này giờ chỉ dùng làm tham chiếu cơ bản.
        # Logic chặn thông minh sẽ tính toán thời gian dựa trên số lần vi phạm.
        self.BLOCK_DURATION = 60
        
        # Dictionary lưu danh sách IP đang bị chặn để quản lý thời gian mở khóa
        self.blocked_ips = {}           
        self.traffic_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        # Lưu thống kê theo từng Switch để tránh bị ghi đè khi nhận nhiều FlowStatsReply
        self.switch_stats = {}
        
        # Dictionary lưu trạng thái cũ của flow (packet_count, byte_count) để tính tốc độ tức thời (PPS)
        self.flow_history = {} 
        
        # Biến lưu kết quả dự đoán mới nhất để hiển thị lên màn hình CLI dashboard
        self.latest_pred = {
            'src': '-', 'dst': '-', 'proto': '-', 
            'rate': 0, 'result': 'Waiting...', 'conf': '-', 'reason': '-',
            'priority': -1
        }
        # Thời điểm và mức ưu tiên khóa hiển thị CLI
        self.pred_lock_until = 0
        self.pred_lock_priority = -1

        self.offender_history = {} 
        
        # --- CẤU HÌNH ĐƯỜNG DẪN FILE LOG ---
        # Tự động tìm đường dẫn thư mục hiện tại để tránh lỗi "File Not Found"
        CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
        # Thư mục chứa log nằm ở cấp cha '../attack_log'
        LOG_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "../attack_log"))
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)

        # Định nghĩa đường dẫn tuyệt đối cho các file log
        self.HISTORY_FILE = os.path.join(LOG_DIR, "offender_history.csv")
        self.DDOS_DATASET_FILE = os.path.join(LOG_DIR, "ddos_captured_dataset.csv")
        self.MANUAL_BLOCK_FILE = os.path.join(LOG_DIR, "manual_blocks.txt")
        self.ATTACK_LOG_FILE = os.path.join(LOG_DIR, "attack_logs.csv")
        self.AI_PREDICT_LOG_FILE = os.path.join(LOG_DIR, "ai_predict.csv")
        self.DEBUG_FILE = "debug_ai_prediction.log"
        
        # Gọi hàm khởi tạo file (tạo header CSV nếu chưa có)
        self._init_files()
        self._init_debug_log()

        # ### TẢI MÔ HÌNH AI (RANDOM FOREST) ###
        print("Loading AI Model...")
        try:
            model_path = os.path.join(CURRENT_DIR, '../models/rf_model.pkl')
            scaler_path = os.path.join(CURRENT_DIR, '../models/scaler.pkl')

            if os.path.exists(model_path):
                # Load model và scaler vào RAM để dự đoán cực nhanh (In-memory inference)
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
        # Hàm này kiểm tra file dataset, nếu chưa có thì tạo mới và ghi dòng tiêu đề (Header)
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

        # Khởi tạo file log AI Predict nếu được bật
        if self.ENABLE_AI_PREDICT_LOG and not os.path.exists(self.AI_PREDICT_LOG_FILE):
            headers = "Timestamp,SrcIP,DstIP,Proto,PPS,AI_Prob_Normal,AI_Prob_Attack,Verdict,Action,Reason\n"
            with open(self.AI_PREDICT_LOG_FILE, "w") as f:
                f.write(headers)
            try: os.chmod(self.AI_PREDICT_LOG_FILE, 0o666)
            except: pass

    # ### SỰ KIỆN: SWITCH KẾT NỐI (HANDSHAKE) ###
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Tạo Flow mặc định (Table-miss): Priority = 0
        # Ý nghĩa: Nếu gói tin không khớp bất kỳ luật nào khác, gửi nó lên Controller (Packet-In)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        # Hàm tiện ích để gửi bản tin FlowMod (Cài đặt luật) xuống Switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # [UPDATED] Hỗ trợ thêm tham số timeout để dùng cho việc chặn
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    # ### SỰ KIỆN: GÓI TIN MỚI (PACKET-IN) ###
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Bỏ qua gói tin LLDP (Link Layer Discovery Protocol) để tránh nhiễu
        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Học địa chỉ MAC: Ghi nhớ Source MAC nằm ở cổng nào
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Tra cứu bảng MAC để tìm cổng ra
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # Nếu chưa biết MAC đích ở đâu, Flood ra tất cả các cổng
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Nếu đã biết đích đến và gói tin là IP
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            # Tạo điều kiện Match chi tiết (IP Src, IP Dst, Proto)
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, 
                                    eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                                    ip_proto=ip_pkt.proto)
            
            # Cài đặt Flow Rule (Priority=1) để Switch tự chuyển tiếp lần sau
            # Điều này giúp giảm tải cho Controller (không phải xử lý Packet-In liên tục cho cùng 1 dòng)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id)
            else:
                self.add_flow(datapath, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # Gửi gói tin hiện tại đi (Packet-Out)
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        # Quản lý danh sách các Switch đang kết nối (để gửi request stats)
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
            if datapath.id in self.switch_stats:
                del self.switch_stats[datapath.id]

    # ### VÒNG LẶP GIÁM SÁT CHÍNH (MONITOR LOOP) ###
    def _monitor(self):
        while True:
            # 1. Kiểm tra và mở khóa các IP đã hết hạn chặn
            current_ts = datetime.now().timestamp()
            expired_ips = [ip for ip, data in self.blocked_ips.items() if current_ts > data['unlock_time']]
            for ip in expired_ips:
                del self.blocked_ips[ip]

            # --- [LOGIC KHÓA HIỂN THỊ CẢNH BÁO] ---
            # Nếu đã hết thời gian khóa, cho phép cập nhật trạng thái mới từ đầu.
            if time.time() >= self.pred_lock_until:
                self.pred_lock_priority = -1
                self.latest_pred['priority'] = -1
            # --------------------------------------
                 
            # 2. Gửi yêu cầu lấy thống kê đến tất cả các Switch
            for dp in self.datapaths.values():
                self._request_stats(dp)
                # 3. Kiểm tra file manual_blocks.txt xem có lệnh chặn thủ công từ Admin không
                self._check_manual_blocks(dp)
            
            # 4. Cập nhật giao diện CLI
            self._print_dashboard()
            
            # Ngủ 1 khoảng thời gian (STATUS_INTERVAL) trước khi lặp lại
            time.sleep(self.STATUS_INTERVAL)


    def _check_manual_blocks(self, datapath):
        # Đọc file txt để lấy IP cần chặn ngay lập tức
        if not os.path.exists(self.MANUAL_BLOCK_FILE): return
        try:
            with open(self.MANUAL_BLOCK_FILE, "r") as f:
                lines = f.readlines()
            # Xóa nội dung file sau khi đọc để tránh chặn lặp lại
            with open(self.MANUAL_BLOCK_FILE, "w") as f: f.write("")
            
            for line in lines:
                ip = line.strip()
                if ip and ip not in self.blocked_ips:
                    self._block_ip(datapath, ip, "Manual-Block", 0)
        except: pass

    def _request_stats(self, datapath):
        # Gửi bản tin OFPFlowStatsRequest
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _get_attack_reason(self, proto, pps):
        # Hàm phụ trợ tạo chuỗi lý do tấn công dựa trên Protocol và PPS
        if pps < self.MIN_PPS_THRESHOLD: return "Normal Traffic"
        if proto == 17: return "UDP Volumetric Flood" if pps > 1000 else "UDP Flood Pattern"
        if proto == 6: return "TCP SYN Flood" if pps > 1000 else "TCP Anomalous Rate"
        if proto == 1: return "ICMP Echo Flood"
        return f"High Packet Rate ({int(pps)} pps)"

    # ### XỬ LÝ PHẢN HỒI THỐNG KÊ (CORE LOGIC) ###
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        # Biến đếm cục bộ cho Switch này
        local_summary = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        current_time = time.time()

        for stat in body:
            # 1. Bỏ qua Priority 0 (Table-miss)
            if stat.priority == 0: continue
            
            # Lấy protocol từ Match
            ip_proto = stat.match.get('ip_proto', 0)

            # --- [FIX LOGIC QUAN TRỌNG] ---
            # Nếu là luật chặn (Priority 100), OpenFlow Match không chứa ip_proto.
            # Ta phải "khôi phục" protocol từ bộ nhớ blocked_ips để đếm cho đúng.
            if stat.priority == 100:
                src_ip = stat.match.get('ipv4_src')
                # Tra cứu ngược lại xem IP này bị chặn vì protocol nào (UDP/TCP/ICMP)
                if src_ip in self.blocked_ips:
                    ip_proto = self.blocked_ips[src_ip].get('proto', 0)
            # ------------------------------
            
            # Tiến hành đếm (Giờ đây ip_proto đã chính xác kể cả khi bị chặn)
            if ip_proto == 1: local_summary['ICMP'] += 1
            elif ip_proto == 6: local_summary['TCP'] += 1
            elif ip_proto == 17: local_summary['UDP'] += 1
            local_summary['Total'] += 1

            # Nếu là luật chặn, chỉ đếm xong rồi bỏ qua, không xử lý AI tiếp
            if stat.priority == 100: continue
            if 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match: continue

            ip_dst = stat.match['ipv4_dst']
            # Kiểm tra IP đích bị chặn (đã đếm ở trên rồi nên continue an toàn)
            if ip_dst in self.blocked_ips: continue

            ip_src = stat.match['ipv4_src']
            packet_count = stat.packet_count
            byte_count = stat.byte_count
            flow_key = (dpid, ip_src, ip_dst, ip_proto)
            
            pps_rate = 0
            bps_rate = 0
            
            # Tính toán tốc độ tức thời (PPS/BPS)
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

            if pps_rate < self.MIN_PPS_THRESHOLD: continue

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

            verdict = "Normal"
            display_priority = 0
            reason = self._get_attack_reason(ip_proto, pps_rate)
            probs = [1.0, 0.0]
            conf_score = 0.0

            if self.model:
                try:
                    features_scaled = self.scaler.transform(features)
                    probs = self.model.predict_proba(features_scaled)[0]
                    conf_score = probs[1]
                    
                    # --- HYBRID ENGINE ---
                    
                    # 1. ATTACK
                    if conf_score >= 0.8 or pps_rate > 500:
                        verdict = "ATTACK"
                        action_status = "BLOCKED"
                        display_priority = 3
                        if conf_score >= 0.8: reason = f"AI Detected ({reason})"
                        else: reason = f"Volumetric Flood > 500pps"
                        
                        self._block_ip(ev.msg.datapath, ip_src, ip_dst, ip_proto)
                        self._log_attack(ip_src, ip_dst, ip_proto, packet_count, label="Attack", reason=reason)
                        self._log_full_dataset(ip_src, ip_dst, ip_proto, stat, pps_rate, bps_rate)

                    # 2. WARNING
                    elif pps_rate > self.MIN_PPS_THRESHOLD or (conf_score > 0.5): 
                        verdict = "WARNING"
                        action_status = "ALERT"
                        display_priority = 2
                        reason = f"Elevated Traffic ({int(pps_rate)} pps)"
                        self._log_attack(ip_src, ip_dst, ip_proto, packet_count, label="Warning", reason=reason)

                    # 3. NORMAL
                    else:
                        verdict = "Normal"
                        display_priority = 1

                    self._log_ai_prediction(ip_src, ip_dst, ip_proto, pps_rate, probs, verdict, action_status, reason)

                    # Cập nhật CLI với cơ chế khóa cảnh báo
                    now_ts = time.time()
                    is_locked = now_ts < self.pred_lock_until
                    
                    if (not is_locked) or (display_priority >= self.pred_lock_priority):
                        self.latest_pred = {
                            'src': ip_src, 'dst': ip_dst, 'proto': ip_proto,
                            'rate': f"{pps_rate:.0f}",
                            'result': verdict,
                            'conf': f"{conf_score:.2f}",
                            'reason': reason,
                            'priority': display_priority
                        }
                        if display_priority >= 2:
                            self.pred_lock_until = now_ts + self.PRED_LOCK_SECONDS
                            self.pred_lock_priority = display_priority

                except Exception as e: 
                    print(f"Error in detection logic: {e}")
        
        # Cập nhật thống kê vào biến toàn cục
        self.switch_stats[dpid] = local_summary
        total = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0}
        for stats in self.switch_stats.values():
            total['TCP'] += stats.get('TCP', 0)
            total['UDP'] += stats.get('UDP', 0)
            total['ICMP'] += stats.get('ICMP', 0)
            total['Total'] += stats.get('Total', 0)
        self.traffic_summary = total

    # Hàm ghi log dự đoán AI chi tiết (bao gồm cả xác suất Normal/Attack)
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

    # Hàm ghi log dataset đầy đủ để dùng cho việc huấn luyện lại mô hình sau này
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
        # Cập nhật lịch sử vi phạm (để hiện bảng Top Offenders)
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

    # ### HÀM CHẶN IP (MITIGATION) ###
    def _block_ip(self, datapath, ip_src, ip_dst, proto):
        current_time = datetime.now().timestamp()
        
        # Nếu IP này đã bị chặn và vẫn còn trong thời gian hiệu lực thì không làm gì cả
        if ip_src in self.blocked_ips:
            if current_time < self.blocked_ips[ip_src]['unlock_time']: return 

        # Xóa flow cũ của IP này trong lịch sử để khi nó quay lại sẽ tính PPS từ đầu
        keys_to_remove = [k for k in self.flow_history if k[1] == ip_src]
        for k in keys_to_remove:
            del self.flow_history[k]

        # Cập nhật lịch sử vi phạm (để lấy số lần vi phạm tính thời gian chặn)
        self._update_offender_history(ip_src, proto)
        
        # --- [INTELLIGENT UNBANNING] Exponential Backoff ---
        # Tính toán thời gian chặn dựa trên số lần vi phạm của IP này
        offense_count = self.offender_history[ip_src]['count']
        
        if offense_count == 1:
            duration = 60       # Lần 1: Chặn 1 phút
        elif offense_count == 2:
            duration = 300      # Lần 2: Chặn 5 phút
        else:
            duration = 1800     # Lần 3+: Chặn 30 phút
            
        self.blocked_ips[ip_src] = {
            'unlock_time': current_time + duration,
            'victim': ip_dst, 'proto': proto,
            'duration': duration # Lưu lại để hiển thị
        }
        
        # Gửi bản tin FlowMod DROP
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src)
        # Action rỗng ([]) nghĩa là DROP gói tin
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        
        # Priority=100 (Cao hơn mức 1 của gói tin thường) để đảm bảo luật này được khớp trước
        # Idle/Hard timeout = duration (tự động xóa sau thời gian phạt)
        mod = parser.OFPFlowMod(datapath=datapath, priority=100, match=match, instructions=inst,
                                idle_timeout=duration, hard_timeout=duration)
        datapath.send_msg(mod)

    def _write_debug_log(self, src, dst, proto, rate, reason, result, action):
        try:
            timestamp = datetime.now().strftime('%H:%M:%S')
            line = f"{timestamp},{src},{dst},{proto},{rate:.0f},{reason},{result},{action}\n"
            with open(self.DEBUG_FILE, "a") as f:
                f.write(line)
        except: pass

    def _log_attack(self, src, dst, proto, pkts, label="Attack", reason="Unknown"):
        # Ghi log tấn công vào file CSV để Dashboard đọc
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

    # ### HÀM IN GIAO DIỆN CLI ###
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
        
        # Hàm in dòng màu đặc biệt cho Alert
        def p_alert_line(label, info_text, color_code):
            # Cấu trúc: [LABEL] Info...
            raw_text = f"[{label}] {info_text}"
            padding = IW - len(raw_text)
            if padding < 0: padding = 0
            # In màu cho Label và giữ text trắng
            print(f"║ {color_code}[{label}]\033[0m {info_text}{' ' * padding} ║")

        print(f"╔{'═'*(W-2)}╗")
        title = "SDN AI-GUARD DASHBOARD"; time_str = f"Time: {now}"
        gap = IW - len(title) - len(time_str)
        if gap < 0: gap = 1
        print(f"║ {title}{' '*gap}{time_str} ║")
        h_line()
        
        p_line("SYSTEM STATUS")
        stats_msg = f"> Total Flows: {self.traffic_summary['Total']} (ICMP:{self.traffic_summary['ICMP']} TCP:{self.traffic_summary['TCP']} UDP:{self.traffic_summary['UDP']})"
        p_line(stats_msg)
        h_line()
        
        p = self.latest_pred
        res = p['result']
        
        p_line("REAL-TIME INSPECTION (AI + Rule Hybrid)")
        p_line(f"Source: {p['src']:<15}  ->  Dest: {p['dst']:<15}")
        
        # [FIX] Logic hiển thị thông minh dựa trên kết quả
        if res == "ATTACK":
            # Màu Đỏ (91m)
            info = f"PPS: {p['rate']} | Conf: {p['conf']} | {p['reason']}"
            p_alert_line("ATTACK", info, "\033[91m")
        elif res == "WARNING":
            # Màu Vàng (93m)
            info = f"PPS: {p['rate']} | Conf: {p['conf']} | {p['reason']}"
            p_alert_line("WARNING", info, "\033[93m")
        else:
            # Màu Xanh (92m) - Normal
            info = f"Proto: {p['proto']} | Rate: {p['rate']} pps"
            p_alert_line("NORMAL", info, "\033[92m")

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
                duration = data.get('duration', 60) # Mặc định 60s nếu không có
                if rem > 0:
                    row = f"🚫 {ip:<15} (Time: {rem}s / {duration}s)"
                    p_line(row)
                    count += 1
        h_line()

        p_line("TOP OFFENDERS (History)")
        if not self.offender_history:
            p_line("[ No history yet ]")
        else:
            # [UPDATED] Thêm dòng tiêu đề cột
            p_line(f"{'No.':<4}{'IP Address':<16}{'Blocks':<8}{'Methods':<20}")
            p_line("-" * (IW))
            
            sorted_hist = sorted(self.offender_history.items(), key=lambda x: x[1]['count'], reverse=True)
            for i, (ip, info) in enumerate(sorted_hist[:3]):
                m = "+".join(list(info['methods']))
                row = f"{i+1:<4}{ip:<16}{info['count']:<8}{m:<20}"
                p_line(row)
        print(f"╚{'═'*(W-2)}╝")